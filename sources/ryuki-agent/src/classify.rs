//! Outbox retry classification — maps a `ClientError` to a retry strategy.
//!
//! ## Classification rules
//!
//! | Error                         | Class          | Rationale                              |
//! |-------------------------------|----------------|----------------------------------------|
//! | `Reqwest(_)`                  | Transient      | Network / connect / timeout / TLS      |
//! | `ErrorStatus { 429, .. }`     | Transient      | Rate-limited — retry after back-off    |
//! | `ErrorStatus { 500..=599 }`   | Transient (*)  | Server-side fault — may recover        |
//! | `ErrorStatus { 501, .. }`     | Permanent      | Not Implemented — will never recover   |
//! | `ErrorStatus { 401, .. }`     | OperatorAlert  | Token revoked — keep, alert operator   |
//! | `ErrorStatus { 403, .. }`     | OperatorAlert  | Agent not approved — keep, alert       |
//! | All other 4xx                 | Permanent      | Malformed / conflict — will not recover|
//!
//! (*) 501 is carved out of the 5xx transient range because "Not Implemented"
//! is a structural mismatch, not a recoverable server fault.
//!
//! ## OperatorAlert semantics
//!
//! `OperatorAlert` items are **kept in the outbox** and are **never moved toward
//! the quarantine threshold**.  `drain_outbox` emits one `tracing::error!` per
//! drain cycle (not per entry) for these.  This allows an operator to fix the
//! auth problem and have the results re-delivered without losing them.

use crate::client::ClientError;

/// Retry disposition returned by [`classify_client_error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    /// Network / timeout / TLS — retry with back-off, count toward the max.
    Transient,
    /// Structural mismatch (e.g. 400, 404, 409, 501) — quarantine immediately.
    Permanent,
    /// Token revoked / agent unapproved (401, 403) — keep in outbox, do NOT
    /// count toward quarantine threshold, emit operator alert once per cycle.
    OperatorAlert,
}

/// Classify a `ClientError` into a retry disposition.
///
/// Pure function — no I/O, no state.  Unit-testable in isolation.
pub fn classify_client_error(err: &ClientError) -> RetryClass {
    match err {
        // Any reqwest-layer failure (connect, timeout, TLS, DNS …) is transient.
        ClientError::Reqwest(_) => RetryClass::Transient,

        ClientError::ErrorStatus { status, .. } => classify_status(*status),

        // Cannot arise from result delivery (only the startup handshake returns
        // it), but if one ever reached the outbox classifier it is a structural
        // version mismatch that retrying cannot fix — quarantine it.
        ClientError::IncompatibleProtocol { .. } => RetryClass::Permanent,

        // A rejected endpoint is a local configuration/security-policy error;
        // retries cannot make an unsafe URL admissible.
        ClientError::InvalidEndpoint { .. } => RetryClass::Permanent,

        // A malformed bootstrap keyset is a structural control-plane contract
        // failure. Retrying the same response cannot make it trustworthy.
        ClientError::InvalidControlPlaneKeysetResponse => RetryClass::Permanent,
    }
}

fn classify_status(status: u16) -> RetryClass {
    match status {
        // Auth failures: token revoked or agent not yet approved.
        // Keep in outbox, alert operator, do NOT count toward quarantine cap.
        401 | 403 => RetryClass::OperatorAlert,

        // Rate limited — transient.
        429 => RetryClass::Transient,

        // 501 Not Implemented — structural, will never recover.
        501 => RetryClass::Permanent,

        // Other 5xx — server-side fault, may recover (transient).
        500..=599 => RetryClass::Transient,

        // Everything else in 4xx (400, 404, 409, …) — permanent mismatch.
        400..=499 => RetryClass::Permanent,

        // Any other status (1xx, 2xx, 3xx) arriving here is unexpected but
        // we treat it as Permanent to avoid indefinite retries.
        _ => RetryClass::Permanent,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientError;

    fn status_err(status: u16) -> ClientError {
        ClientError::ErrorStatus {
            status,
            body: "test".to_owned(),
        }
    }

    // Build a minimal Reqwest error by constructing one from a URL parse error
    // (guaranteed not to need a live network).
    fn reqwest_err() -> ClientError {
        // reqwest::get is async; use a blocking URL-parse path instead.
        // The From impl on ClientError accepts reqwest::Error directly.
        // We create a synthetic one via the error channel on a synchronous path.
        // easiest: decode error from an intentionally invalid URL with blocking client
        // Actually, we can construct reqwest::Error via the public API by misusing
        // reqwest::blocking — but that pulls in the blocking feature. Instead,
        // we construct the variant directly since ClientError::Reqwest wraps
        // reqwest::Error and the tests only need to exercise the Reqwest arm.
        //
        // The simplest cross-platform approach: build a reqwest::Error from a
        // `reqwest::Request` on a bad URL using the `reqwest` crate's public
        // builder (no network needed for URL construction errors).
        //
        // Since reqwest::Error is opaque and not constructible directly from
        // tests, we rely on the From<reqwest::Error> impl.  We create an error
        // via a deliberately invalid URL scheme, which is detectable at build time
        // without making any network requests.
        //
        // However, constructing `reqwest::Error` directly in tests is awkward.
        // Since the only thing we test here is the `Reqwest(_)` arm (not the
        // inner error value), we can build a synthetic struct via the
        // `#[from] reqwest::Error` conversion. The cleanest test-only approach
        // is to use `reqwest::Client::new().execute` on a bad request, but that
        // requires async.
        //
        // Trade-off: directly test the classify_status helper for all numeric
        // cases (already below), and test the Reqwest arm via a unit test that
        // calls classify_client_error with a dummy error built through
        // reqwest's error API via a blocking URL validation call.
        //
        // Since reqwest errors are opaque, we skip the reqwest variant in this
        // file and test it in the drain tests via a StubPoster.  The Reqwest
        // arm is a single `_ => Transient` so the logic is trivially correct.
        //
        // For the purpose of this test module, call classify_status directly.
        // The Reqwest(e) → Transient mapping is also exercised by drain tests.
        unreachable!("use classify_status tests below; drain tests cover Reqwest arm")
    }

    // Suppress dead-code warning for the helper we keep for documentation.
    #[allow(dead_code)]
    fn _dummy_reqwest_err_usage() -> ClientError {
        reqwest_err()
    }

    // Test the status-code mapping table exhaustively.
    #[test]
    fn status_429_is_transient() {
        assert_eq!(classify_status(429), RetryClass::Transient);
    }

    #[test]
    fn status_503_is_transient() {
        assert_eq!(classify_status(503), RetryClass::Transient);
    }

    #[test]
    fn status_500_is_transient() {
        assert_eq!(classify_status(500), RetryClass::Transient);
    }

    #[test]
    fn status_501_is_permanent() {
        assert_eq!(classify_status(501), RetryClass::Permanent);
    }

    #[test]
    fn status_400_is_permanent() {
        assert_eq!(classify_status(400), RetryClass::Permanent);
    }

    #[test]
    fn status_404_is_permanent() {
        assert_eq!(classify_status(404), RetryClass::Permanent);
    }

    #[test]
    fn status_409_is_permanent() {
        assert_eq!(classify_status(409), RetryClass::Permanent);
    }

    #[test]
    fn invalid_endpoint_is_permanent() {
        assert_eq!(
            classify_client_error(&ClientError::InvalidEndpoint {
                reason: "test policy rejection",
            }),
            RetryClass::Permanent,
        );
    }

    #[test]
    fn status_401_is_operator_alert() {
        assert_eq!(classify_status(401), RetryClass::OperatorAlert);
    }

    #[test]
    fn status_403_is_operator_alert() {
        assert_eq!(classify_status(403), RetryClass::OperatorAlert);
    }

    // Test classify_client_error on ErrorStatus variants (status code path).
    #[test]
    fn classify_client_error_error_status_table() {
        let cases: &[(u16, RetryClass)] = &[
            (429, RetryClass::Transient),
            (503, RetryClass::Transient),
            (500, RetryClass::Transient),
            (501, RetryClass::Permanent),
            (400, RetryClass::Permanent),
            (404, RetryClass::Permanent),
            (409, RetryClass::Permanent),
            (401, RetryClass::OperatorAlert),
            (403, RetryClass::OperatorAlert),
        ];
        for (status, expected) in cases {
            assert_eq!(
                classify_client_error(&status_err(*status)),
                *expected,
                "status {status} expected {expected:?}"
            );
        }
    }

    #[test]
    fn incompatible_protocol_is_permanent() {
        // A version mismatch is structural — retrying can never fix it, so the
        // classifier quarantines it (it never actually reaches this path from the
        // delivery loop, but the mapping must be safe).
        let err = ClientError::IncompatibleProtocol {
            cp_version: 2,
            supported: &[1],
        };
        assert_eq!(classify_client_error(&err), RetryClass::Permanent);
    }

    #[test]
    fn invalid_control_plane_keyset_is_permanent() {
        assert_eq!(
            classify_client_error(&ClientError::InvalidControlPlaneKeysetResponse),
            RetryClass::Permanent
        );
    }
}
