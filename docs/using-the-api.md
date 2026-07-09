# Using the API

Everything the portal does, it does through this API, and everything the API serves is available to your own tooling: the same authentication, the same permission tiers, the same audited lifecycle. This guide covers how to authenticate, the conventions every endpoint follows, and a complete request lifecycle you can run with curl. The [API Reference](api-reference.md) documents every route by area.

## Base URL and versioning

All routes live under `/api` on the control plane (the same origin the portal is served behind). Every response carries an `x-api-version` header. Health lives at `/health` and readiness at `/ready`, both unauthenticated.

## Authentication

The API supports three ways in, selected by the platform's `RYUKI_AUTH_MODE` (see [Configuration](configuration.md)):

**Development modes** (`mock-dry-run`, the default, and `static-dry-run`): requests run as a static admin session with no credentials. Nothing to configure; never run these against anything real.

**Local accounts** (`local`): sign in and use the returned session.

```bash
# Sign in: the response sets a ryuki_session cookie and returns the session id
curl -s -c cookies.txt -X POST https://<host>/api/auth/local/login \
  -H "Content-Type: application/json" \
  -d '{"username": "<user>", "password": "<password>"}'

# Subsequent calls: send the cookie (or the X-Ryuki-Session-Id header)
curl -s -b cookies.txt https://<host>/api/requests
```

**Entra ID** (`entra-id`): browsers use the sign-in flow behind the portal's "Sign in with Microsoft Entra ID" button; non-interactive callers present a bearer JWT from the tenant, validated against its JWKS.

```bash
curl -s https://<host>/api/requests -H "Authorization: Bearer <entra-jwt>"
```

**API tokens** work in every mode and are the right choice for integrations. An admin mints one; the `ryk_...` value is returned exactly once. Tokens can carry site and environment scopes, which narrow everything the token sees — the recommended blast-radius control.

```bash
curl -s -b cookies.txt -X POST https://<host>/api/admin/tokens \
  -H "Content-Type: application/json" \
  -d '{"name": "ci-reader", "owner_principal": "ci@example.test", "roles": ["Auditor"], "site_scope": "DEFRA"}'

curl -s https://<host>/api/requests -H "Authorization: Bearer ryk_..."
```

## Authorization

Every route is gated by one of five permission tiers — `admin`, `approve`, `execute`, `request`, `audit` — derived from your roles, and results are narrowed by your site and environment scopes. The enforcement semantics (when you get a 404 versus a 403 versus a silently narrowed list) are documented in [RBAC & Scoping](rbac-and-scoping.md); the per-route tier appears in the [API Reference](api-reference.md).

## Conventions

**Errors** are a consistent JSON body with a stable machine code and a human message, plus an optional detail:

```json
{ "error": "VALIDATION_FAILED", "message": "site is not active", "detail": "..." }
```

`4xx` means your request cannot succeed as sent (wrong tier, wrong mode, invalid payload — do not retry unchanged). `5xx` is the platform's problem. The public agent-protocol surface additionally documents RFC 9457-shaped errors in the [OpenAPI spec](api-reference.md).

**Pagination**: list endpoints accept `limit` (default 500, clamped to 1..1000) and `offset`. Object-shaped responses add `total`, `limit`, and `offset` keys; bare-array responses carry the filtered total in an `X-Total-Count` header instead. Totals are filtered and scope-aware, never whole-table counts.

**Timestamps** are RFC 3339 strings. **Degraded behavior**: without a database, read endpoints respond with `source: "no-db"` and empty data rather than fabricating rows, and writes return 503.

## Walkthrough: a request through its lifecycle

The heart of the platform is the governed request lifecycle. This runs end-to-end on a dev stack (`RYUKI_AUTH_MODE=mock-dry-run`, so no auth headers are needed; add yours in real modes).

```bash
BASE=http://localhost:8080

# 1. Create a request (server deployment intake)
REQ=$(curl -s -X POST $BASE/api/requests \
  -H "Content-Type: application/json" \
  -d '{
    "request_type": "server-deployment",
    "site": "DEFRA",
    "environment": "prod",
    "name": "app-server-01",
    "fields": {"operating_system": "linux"}
  }' | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])")

# 2. Walk the governed stages
curl -s -X POST $BASE/api/requests/$REQ/validate   # static checks against catalog contracts
curl -s -X POST $BASE/api/requests/$REQ/plan       # execution plan with impact and rollback
curl -s -X POST $BASE/api/requests/$REQ/approve    # role-based approval (separation of duties applies)
curl -s -X POST $BASE/api/requests/$REQ/lock       # change window locked, resources reserved
curl -s -X POST $BASE/api/requests/$REQ/execute    # dispatches agent jobs, dry-run by default
curl -s -X POST $BASE/api/requests/$REQ/verify     # post-change health probes
# execution completes asynchronously once the agent posts its result

# 3. Read the state, the audit trail, and the sealed evidence pack
curl -s $BASE/api/requests/$REQ                    # status, stages, steps[] when orchestrated
curl -s $BASE/api/requests/$REQ/audit              # hash-chained transition trail (audit tier)
curl -s $BASE/api/requests/$REQ/evidence           # redacted, digest-sealed evidence pack
```

Every transition is CAS-guarded (a conflicting transition answers 409), attributed, and appended to the hash-chained audit trail — including the agent-driven `executing` transition, which is recorded under the machine identity of the agent whose signed result caused it.

From here: multi-step requests and per-step live approvals are covered in [Multi-Step Orchestration](orchestration.md), and taking execution to real infrastructure in [Agents & Live Execution](agents-and-live-execution.md).
