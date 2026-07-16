-- A successful LivePlan has two evidence inputs at ingestion:
--
-- * `evidence_blobs.bytes` contains the signed, digest-verified safe projection
--   used by the server-side review path.
-- * `agent_jobs.evidence_json` was a parallel, unsigned convenience field and
--   could contain raw provider data even when the signed bytes were safe.
--
-- Migration 189 introduced `raw_plan_digest` together with the safe-projection
-- validation path. Rows without a complete post-189 storage shape cannot be
-- reconstructed safely in SQL, so they are detached from any evidence blob and
-- explicitly quarantined instead of guessing whether their bytes were redacted.

-- Match the ingestion transaction's evidence_blobs -> agent_jobs write order.
-- SHARE ROW EXCLUSIVE blocks concurrent result writes while the one-time
-- classification, detach, and delete are performed as one migration transaction.
LOCK TABLE evidence_blobs, agent_jobs IN SHARE ROW EXCLUSIVE MODE;

CREATE TEMPORARY TABLE ryuki_live_plan_evidence_quarantine
ON COMMIT DROP
AS
SELECT
    jobs.id,
    jobs.evidence_digest,
    jobs.raw_plan_digest
FROM agent_jobs AS jobs
WHERE jobs.mode = 'LivePlan'
  AND jobs.status = 'Succeeded'
  AND jobs.result_status = 'planned'
  AND NOT (
      jobs.raw_plan_digest IS NOT NULL
      AND COALESCE(jobs.evidence_digest ~ '^[0-9a-f]{64}$', FALSE)
      AND jobs.signed_envelope IS NOT NULL
      AND EXISTS (
          SELECT 1
          FROM evidence_blobs AS blob
          WHERE blob.digest = jobs.evidence_digest
            AND blob.size_bytes = octet_length(blob.bytes)
      )
  );

-- No successful LivePlan may retain the independently untrusted inline JSON,
-- including otherwise-valid post-189 rows written before this fix deployed.
UPDATE agent_jobs
SET evidence_json = NULL,
    updated_at = NOW()
WHERE mode = 'LivePlan'
  AND status = 'Succeeded'
  AND evidence_json IS NOT NULL;

-- Fail closed for unverifiable legacy rows. The signed envelope remains as
-- non-raw forensic metadata, but neither review nor approval can resolve bytes
-- through the job after both commitments are detached.
UPDATE agent_jobs AS jobs
SET evidence_digest = NULL,
    raw_plan_digest = NULL,
    updated_at = NOW()
FROM ryuki_live_plan_evidence_quarantine AS quarantine
WHERE jobs.id = quarantine.id;

-- Remove a detached legacy blob only when no other job still owns the same
-- content-addressed digest. A shared blob is an explicit trusted-review residual;
-- deleting it here would silently destroy another mode/job's retained evidence.
DELETE FROM evidence_blobs AS blob
USING (
    SELECT DISTINCT evidence_digest
    FROM ryuki_live_plan_evidence_quarantine
    WHERE evidence_digest IS NOT NULL
) AS detached
WHERE blob.digest = detached.evidence_digest
  AND NOT EXISTS (
      SELECT 1
      FROM agent_jobs AS owner
      WHERE owner.evidence_digest = blob.digest
  );

-- Store only a server-authored quarantine marker, never any original JSON or
-- bytes. The marker records whether a shared digest remains for trusted review.
UPDATE agent_jobs AS jobs
SET evidence_json = jsonb_strip_nulls(jsonb_build_object(
        '_live_plan_evidence_state', 'quarantined-unverifiable-legacy',
        '_former_evidence_digest', CASE
            WHEN quarantine.evidence_digest ~ '^[0-9a-f]{64}$'
            THEN quarantine.evidence_digest
        END,
        '_former_raw_plan_digest', CASE
            WHEN quarantine.raw_plan_digest ~ '^[0-9a-f]{64}$'
            THEN quarantine.raw_plan_digest
        END,
        '_detached_blob_state', CASE
            WHEN quarantine.evidence_digest IS NULL THEN 'not-recorded'
            WHEN EXISTS (
                SELECT 1
                FROM evidence_blobs AS blob
                WHERE blob.digest = quarantine.evidence_digest
            ) THEN 'retained-shared-digest-trusted-review'
            ELSE 'removed-or-not-present'
        END
    )),
    updated_at = NOW()
FROM ryuki_live_plan_evidence_quarantine AS quarantine
WHERE jobs.id = quarantine.id;

-- Fence both vulnerable shapes after cleanup:
--
-- * current `planned` results have commitments plus no inline JSON;
-- * other successful LivePlan outcomes have no raw-plan commitment or inline
--   JSON; or
-- * unverifiable legacy `planned` rows have no commitments and only the exact
--   quarantine marker written above.
--
-- An older writer cannot reintroduce raw inline JSON or attach fresh evidence to
-- a pre-189 successful LivePlan after this migration commits.
ALTER TABLE agent_jobs
    ADD CONSTRAINT agent_jobs_live_plan_evidence_storage_check
    CHECK (
        mode <> 'LivePlan'
        OR status <> 'Succeeded'
        OR (
            result_status IS DISTINCT FROM 'planned'
            AND raw_plan_digest IS NULL
            AND evidence_json IS NULL
        )
        OR (
            result_status = 'planned'
            AND (
                (
                    raw_plan_digest IS NOT NULL
                    AND COALESCE(evidence_digest ~ '^[0-9a-f]{64}$', FALSE)
                    AND signed_envelope IS NOT NULL
                    AND evidence_json IS NULL
                )
                OR (
                    raw_plan_digest IS NULL
                    AND evidence_digest IS NULL
                    AND COALESCE(jsonb_typeof(evidence_json) = 'object', FALSE)
                    AND (
                        evidence_json - ARRAY[
                            '_live_plan_evidence_state',
                            '_former_evidence_digest',
                            '_former_raw_plan_digest',
                            '_detached_blob_state'
                        ]::TEXT[]
                    ) = '{}'::jsonb
                    AND COALESCE(
                        evidence_json->>'_live_plan_evidence_state'
                            = 'quarantined-unverifiable-legacy',
                        FALSE
                    )
                    AND COALESCE(
                        evidence_json->>'_detached_blob_state' IN (
                            'not-recorded',
                            'retained-shared-digest-trusted-review',
                            'removed-or-not-present'
                        ),
                        FALSE
                    )
                    AND (
                        NOT (evidence_json ? '_former_evidence_digest')
                        OR COALESCE(
                            evidence_json->>'_former_evidence_digest'
                                ~ '^[0-9a-f]{64}$',
                            FALSE
                        )
                    )
                    AND (
                        NOT (evidence_json ? '_former_raw_plan_digest')
                        OR COALESCE(
                            evidence_json->>'_former_raw_plan_digest'
                                ~ '^[0-9a-f]{64}$',
                            FALSE
                        )
                    )
                )
            )
        )
    );

COMMENT ON CONSTRAINT agent_jobs_live_plan_evidence_storage_check ON agent_jobs IS
    'Successful LivePlans retain no untrusted inline JSON; unverifiable legacy evidence is detached and explicitly quarantined.';
