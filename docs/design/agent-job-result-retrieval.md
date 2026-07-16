# Agent-job result retrieval — GET the signed attestation + result metadata

Status: SHIPPED (codex plan APPROVE; codex impl review NEEDS-CHANGES×2 → APPROVE). Plan
refinements folded in — (1) parse the uuid BEFORE get_db so a malformed id 404s even with no
DB; (2) the happy test asserts the serialized body has NO sentinel-secret substring AND
top-level evidence_digest == signed_envelope.evidence_digest; (3) HARDENING: deserialize the
stored JSONB into the typed `ryuki_protocol::SignedEnvelope` and reserialize, pinning the
response to known attestation fields rather than raw JSONB. Impl-review fixes (see the
"Ingestion guard" section + the Tests below): the `redaction_policy_version` CLOSED-allowlist
guard at BOTH ingestion (Step 5b) and the read side (defense-in-depth), and the `check_ok`
result_status casing. 2nd verify-first analysis swarm (2026-06-29 run 2), CONFIRMED H. VERIFIED: agents POST their result to `/api/agents/{agent_id}/jobs/{job_id}/
result`, which stores `result_status`, `completed_at`, `result_id`, `evidence_digest`,
`evidence_json`, `signed_envelope` on `agent_jobs` (mig 055/121/127). But NO GET surfaces the
result: `GET /api/admin/agents` (agents.rs:2320) and `GET /api/requests/{id}/execution-job`
(contracts.rs:15551) return only metadata (status/result_status/evidence_digest), never the
signed attestation. So an operator can see a job SUCCEEDED but cannot retrieve its signed,
verifiable result. Additive: NO migration, NO engine change.

## Secret hygiene — expose the ATTESTATION, NOT the raw evidence (the crux)
`SignedEnvelope` (ryuki-protocol types.rs:280) is a pure CRYPTOGRAPHIC ATTESTATION:
agent_id/agent_enrollment_id/platform/job_id/attempt_id/lease_generation/request_id/result_id, mode, status,
`job_spec_digest`, `approved_plan_digest`, `evidence_digest` (SHA-256 of the POST-REDACTION
evidence pack), `redaction_policy_version`, timestamp, `key_id`, `cp_nonce`, and the Ed25519
`signature`. It contains ONLY digests + signature + metadata — NO raw evidence, NO secrets,
NO credentials. SAFE to expose to an admin.

`evidence_json` is a SEPARATE, agent-submitted FREE-FORM `Option<Value>` (the raw evidence
payload). The agent applies the redaction policy (`redaction_policy_version`), but there is
NO server-side guarantee that `evidence_json` is redacted — a buggy/compromised agent could
have put sensitive data in it. The dead-lettered list (agents.rs:2486) deliberately EXCLUDES
secret-bearing columns (`spec`, `live_context`) for exactly this reason. So this slice does
NOT expose `evidence_json` (nor `spec`/`live_context`). A redacted-evidence view (with a
server-side redaction guarantee or an explicit policy caveat) is a deliberate FOLLOW-UP.

What operators get: the VERIFIABLE signed result (the attestation proves the agent's signed
outcome; the `evidence_digest` can be cross-checked against the redacted evidence pack via
the existing evidence-verify path) + the result metadata. That is the audit/compliance value
without the raw-payload leak risk.

### Ingestion guard on `redaction_policy_version` (codex impl review, MAJOR)
The read view re-serialises the TYPED `SignedEnvelope`, so it strips stray JSONB keys — but it
still returns every KNOWN field. Of those, `agent_id` / `platform` / `key_id` / `cp_nonce` are
all cross-checked against authoritative CP state at ingestion (the POST verifier), so they
cannot carry arbitrary text. `redaction_policy_version` is the ONE string field with no such
counterpart — a buggy/compromised agent could sign a secret into it and it would ride through
to this view. So the POST verifier now gates it (Step 5b, fail-closed like every other check)
against the CLOSED allowlist of policy versions the CP recognises —
`ryuki_protocol::SUPPORTED_REDACTION_POLICY_VERSIONS` (currently
`["ryuki-redaction-v2"]`, the value the real agent emits via
`ryuki_protocol::REDACTION_POLICY_VERSION`). A charset/length heuristic was NOT enough (codex
2nd pass): a bare token like `SUPERSECRET` is alphanumeric and short, so it would have passed —
only an exact-match allowlist actually closes the channel. The value is an opaque SLUG, not a
semver number (the prior type doc said "semver, e.g. 1.0.0", which was wrong — corrected). A
validly-signed envelope whose policy version is not on the allowlist is rejected with 400 and
nothing is recorded; this both closes the free-form channel and refuses evidence redacted under
a policy the CP cannot interpret. Bumping the policy means replacing the one protocol constant
and its closed allowlist; policies with known redaction gaps are intentionally not retained for
compatibility. Both the agent and the CP reference that shared contract (no drift).

## Endpoint — GET /api/admin/agents/jobs/{job_id}/result
`admin_agent_job_result(Extension<AuthSession>, Path(job_id))`, mirroring
`admin_agent_queue_depth` / `admin_requeue_dead_lettered_job`:
1. EXPLICIT `check_permission(&session, "admin")` → 403 (GET routes under /api/admin/ may not
   be RBAC-gated). NO scope guard — agent jobs are platform-scoped, admin-wide (like the
   dead-lettered list).
2. parse uuid → 404 (BEFORE `get_db`, so a malformed id 404s even with no DB);
   then `get_db()` → 503.
3. `SELECT result_status, completed_at, result_id, evidence_digest, signed_envelope FROM
   agent_jobs WHERE id = $1` (a `FromRow` with `signed_envelope: Option<serde_json::Value>`,
   `result_status/result_id/evidence_digest: Option<...>`, `completed_at: Option<DateTime>`).
   NOTE the SELECT does NOT include `evidence_json`, `spec`, or `live_context`.
   - `None` (no such job) → 404.
   - Some but `signed_envelope IS NULL` (job not terminal / no result yet) → 404 "no result
     recorded for this job yet".
   - Some with a result → 200 `{ job_id, result_status, completed_at: <rfc3339>, result_id,
     evidence_digest, signed_envelope: <the attestation JSON> }`.

## Route
`.route("/api/admin/agents/jobs/{job_id}/result", get(admin_agent_job_result))` — static
`jobs` in the `{agent_id}` slot (same matchit pattern as the just-shipped
`/jobs/{job_id}/priority`; route-tree smoke confirms no collision).

## Tests (agents.rs db tests + a no-DB 403)
1. **happy** (DB, handler_pool + DB_TEST_SERIAL): seed a job and UPDATE its result columns
   (`result_status='check_ok'` — the lowercase label the mig 055 CHECK + the production POST
   store; the job-level `status` is `Succeeded`, distinct from the result-level label —
   completed_at, result_id, evidence_digest, signed_envelope JSONB + ALSO set evidence_json to a
   SENTINEL secret value); GET → 200 with signed_envelope + evidence_digest + result_status
   present; and assert the response has NO `evidence_json` / `spec` / `live_context` keys (the
   sentinel secret does NOT appear).
2. **no-result** (DB): a Pending job (signed_envelope NULL) → 404.
3. **unknown** (DB/no-DB): unknown job_id → 404.
4. **403** (no-DB): a non-admin session → 403.
5. **allowlist guard** (no-DB, pure): `redaction_policy_version_is_supported` accepts only
   `ryuki-redaction-v2` and rejects the superseded v1 policy, bare tokens (`SUPERSECRET`,
   `tokenabc123def456`), unknown semvers/slugs, and empty values.
6. **ingestion rejection** (DB): a VALIDLY-SIGNED envelope smuggling `SUPERSECRET` into
   `redaction_policy_version` is POSTed → 400 (Step 5b), the error names the field, the rejection
   body does not echo the secret, and NO result column is written (fail-closed).

## Files
- sources/ryuki-api/src/agents.rs (admin_agent_job_result + a JobResultRow FromRow + route +
  Step 5b ingestion guard + tests). NO migration, NO engine change.
- sources/ryuki-protocol/src/types.rs (`REDACTION_POLICY_VERSION` +
  `SUPPORTED_REDACTION_POLICY_VERSIONS` — the shared CP/agent allowlist).
- sources/ryuki-agent/src/result.rs (its `REDACTION_POLICY_VERSION` now aliases the protocol
  constant; run.rs/outbox.rs test fixtures reference it too — no drift).

## Out of scope
- Exposing the raw `evidence_json` / execution logs (a redacted-evidence view — a separate
  slice once a server-side redaction guarantee or an explicit caveat is in place).
- A by-request variant (GET the result via /api/requests/{id}/... — execution-job already
  gives the metadata; the attestation could be added there later).
