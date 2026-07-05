//! Evidence blob-store offload decision (#60 slice 1) — the PURE size-threshold core.
//!
//! A live-execution result's evidence — especially the UNTRUNCATED `terraform
//! show -json` plan document, which is deliberately kept whole because it is the
//! plan-integrity digest input and can be multiple megabytes — is persisted inline
//! in the hot `agent_jobs` row (`evidence_json` JSONB). That row is updated
//! frequently across a job's lease/run lifecycle, so a multi-MB inline payload
//! bloats it (Postgres TOASTs the value out-of-line and every update contends with
//! it). Missing-feature #60 offloads LARGE evidence to a content-addressed blob
//! table — keyed by the already-computed-and-verified `evidence_digest`, so
//! identical evidence dedups — and keeps only a small reference inline.
//!
//! This module is the pure, no-IO decision at the heart of that: given the
//! evidence size and a threshold, does the payload stay INLINE or offload to the
//! BLOB store? Keeping it pure means the decision is fully unit-testable with no DB
//! / axum / agent coupling. The `evidence_blobs` table plus the write-offload and
//! read-resolve wiring is a follow-up slice built on this core (the same
//! engine-core-first shape as `post_apply` / `job_orchestration`). Note: the read
//! side is design-gated — exposing raw evidence reopens the deliberately-deferred
//! "no server-side redaction guarantee" concern that keeps `evidence_json` out of
//! the admin result view today — so slice 2 is write-offload first.

/// Where a result's evidence payload should be stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceStorage {
    /// Small enough to keep inline in the `agent_jobs.evidence_json` column.
    Inline,
    /// Large — offload to the content-addressed `evidence_blobs` table, keeping
    /// only a digest reference inline.
    Blob,
}

impl EvidenceStorage {
    /// True when the evidence should be offloaded to the blob store.
    pub fn is_offloaded(self) -> bool {
        matches!(self, EvidenceStorage::Blob)
    }
}

/// Default inline/offload threshold in bytes. Evidence AT OR BELOW this stays
/// inline; strictly larger offloads to the blob store. 64 KiB sits comfortably
/// above small structured results and the runner's 32 KiB human-log cap, yet far
/// below the 10 MiB HTTP body limit — so only genuinely large artifacts (a full
/// `terraform show -json` plan) offload, keeping the hot row lean without churning
/// tiny payloads through a second table.
pub const DEFAULT_EVIDENCE_INLINE_THRESHOLD_BYTES: usize = 64 * 1024;

/// Decide whether evidence of `size_bytes` should be offloaded to the blob store.
///
/// At or below `threshold_bytes` ⇒ [`EvidenceStorage::Inline`]; strictly above ⇒
/// [`EvidenceStorage::Blob`]. The boundary is inclusive-inline (`<=` stays inline)
/// so a payload exactly at the threshold does not offload — the offload cost is
/// only paid once the payload is genuinely over the bar.
pub fn decide_evidence_storage(size_bytes: usize, threshold_bytes: usize) -> EvidenceStorage {
    if size_bytes > threshold_bytes {
        EvidenceStorage::Blob
    } else {
        EvidenceStorage::Inline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_or_below_threshold_stays_inline() {
        // Zero, well-under, and exactly-at the threshold all stay inline.
        assert_eq!(decide_evidence_storage(0, 100), EvidenceStorage::Inline);
        assert_eq!(decide_evidence_storage(50, 100), EvidenceStorage::Inline);
        assert_eq!(decide_evidence_storage(100, 100), EvidenceStorage::Inline);
    }

    #[test]
    fn above_threshold_offloads_to_blob() {
        assert_eq!(decide_evidence_storage(101, 100), EvidenceStorage::Blob);
        assert_eq!(
            decide_evidence_storage(10 * 1024 * 1024, 100),
            EvidenceStorage::Blob
        );
    }

    #[test]
    fn default_threshold_boundaries() {
        let t = DEFAULT_EVIDENCE_INLINE_THRESHOLD_BYTES;
        // A small structured result and the 32 KiB log cap stay inline.
        assert_eq!(
            decide_evidence_storage(2 * 1024, t),
            EvidenceStorage::Inline
        );
        assert_eq!(
            decide_evidence_storage(32 * 1024, t),
            EvidenceStorage::Inline
        );
        assert_eq!(decide_evidence_storage(t, t), EvidenceStorage::Inline);
        // A multi-MB terraform plan offloads.
        assert_eq!(decide_evidence_storage(t + 1, t), EvidenceStorage::Blob);
        assert_eq!(
            decide_evidence_storage(4 * 1024 * 1024, t),
            EvidenceStorage::Blob
        );
    }

    #[test]
    fn is_offloaded_reflects_the_variant() {
        assert!(!EvidenceStorage::Inline.is_offloaded());
        assert!(EvidenceStorage::Blob.is_offloaded());
    }
}
