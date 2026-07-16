# Interactive human authority cutover

Migration 182 replaces ambiguous interactive-session scope with a mandatory,
versioned provider-neutral assignment. It is intentionally a non-overlap
cutover with short API downtime; it is not an expand/contract migration.

## Before migration

1. Prepare governed assignments keyed by the exact stable `(provider, issuer,
   subject)` values. Do not key or link authority by email, display name, group
   label, tenant display name, or another mutable provider field.
2. For Local mode, set both `RYUKI_LOCAL_AUTH__SITE_AUTHORITY` and
   `RYUKI_LOCAL_AUTH__ENVIRONMENT_AUTHORITY` to explicit `global` or `scoped`.
   Scoped axes also require their corresponding comma-separated scope list.
3. Stop every API replica and wait for its database transactions to exit. A
   pre-182 direct Entra bearer path does not consult PostgreSQL and cannot be
   fenced by a database constraint.
4. Confirm the deployment strategy is `Recreate`, take the approved database
   backup, and record the coupled database/binary rollback artifacts.

## Apply and verify

1. Apply migration 182 while no old API replica is running. It deletes every
   existing interactive session, fences the old `active` identity generation,
   quarantines existing identities as Unknown or preserves Revoked, and
   permanently soft-revokes every pre-cutover API token whose human issuer
   generation cannot be proved. Token rows remain immutable audit evidence.
2. Start only the migration-182-aware API generation. Startup reconciles Local
   assignments; federated identities remain unable to sign in until the
   governed assignment source has written and read back an Active assignment.
3. Confirm there are no legacy identity states or ambiguous active axes:

   ```sql
   SELECT COUNT(*) FROM identity_authorities
   WHERE authority_status NOT IN ('active-scoped-v2', 'revoked');

   SELECT COUNT(*) FROM human_authority_assignments
   WHERE assignment_status = 'active'
     AND (site_authority_mode NOT IN ('global', 'scoped')
       OR environment_authority_mode NOT IN ('global', 'scoped'));

   SELECT COUNT(*) FROM api_tokens
   WHERE token_valid
     AND (revoked_at IS NOT NULL
       OR issued_by_provider IS NULL
       OR issued_by_issuer IS NULL
       OR issued_by_subject IS NULL
       OR issued_by_identity_epoch IS NULL
       OR issued_by_human_authority_version IS NULL
       OR cardinality(issued_by_roles) = 0
       OR issued_by_site_authority_mode NOT IN ('global', 'scoped')
       OR issued_by_environment_authority_mode NOT IN ('global', 'scoped')
       OR expires_at IS NULL
       OR expires_at <= created_at
       OR expires_at > created_at + INTERVAL '24 hours');
   ```

4. Exercise local and each enabled federated carrier with approved synthetic
   identities. Prove same-scope admission, cross-site and cross-environment
   denial, role intersection, assignment version invalidation, revocation, and
   session lookup through header, bearer, and cookie carriers.
5. Observe the Recreate downtime and successful new-replica readiness. Do not
   claim multi-replica or live-IdP acceptance from repository tests alone.

## Rollback

Rollback is coupled and session-invalidating:

1. Stop every migration-182-aware reader and wait for transactions to exit.
2. Disable or rotate every old direct-bearer application, audience, signing
   key, and client credential at the upstream identity provider. Obtain
   provider readback proving that the old token generation can no longer be
   minted. If issued access tokens cannot be revoked, wait at least their
   configured maximum lifetime before continuing.
3. Invalidate every API-side bearer-verifier cache and credential generation.
   Under schema 182, soft-revoke persisted API tokens and delete interactive
   sessions; token hard deletion is intentionally rejected so evidence remains.
4. Restore the approved pre-182 database schema and matching binary together.
5. Delete every restored `sessions` and `api_tokens` row before any old binary
   starts. Retaining a pre-cutover credential can resurrect the very
   Unknown-versus-Global ambiguity removed by migration 182.
6. Re-read the IdP application/audience state and prove the disabled old token
   generation is still unavailable. Record the readback and expiry boundary in
   the rollback evidence.
7. Start the old binary only after every invalidation and readback step has
   completed, then require every human user to authenticate again through the
   explicitly approved rollback carrier.

Never run old and new API generations concurrently, downgrade only the binary,
or restore only an old data snapshot. Those states are unsupported and unsafe.
If the IdP cannot prove old application/audience disablement or the maximum
issued-bearer lifetime is unknown, rollback is prohibited rather than guessed.
