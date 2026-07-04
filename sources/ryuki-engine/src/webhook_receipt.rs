//! Inbound webhook signature verification (#18 slice 1) — the PURE security core.
//!
//! External systems (ServiceNow, monitoring, CI) authenticate an inbound webhook
//! by signing the RAW request body with a shared secret (HMAC-SHA256) and sending
//! the hex digest in a header (the `X-Hub-Signature-256: sha256=<hex>` convention).
//! This module is the pure, no-IO verifier: given the shared secret, the EXACT raw
//! body bytes, and the provided signature, it returns whether the signature is
//! valid — using a CONSTANT-TIME comparison so a bad signature leaks no timing
//! information about how much of the digest matched.
//!
//! Keeping this pure means the security-critical primitive is fully unit-testable
//! (against published HMAC test vectors + tamper cases) with no DB, no axum, and no
//! network. The CP handler that looks up the integration connection, resolves its
//! secret, verifies the raw body here, and records a domain event on success (401
//! on mismatch, mutate nothing) is a thin follow-up slice built on this core.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Verify an HMAC-SHA256 signature over `raw_body` using the shared `secret`.
///
/// `provided_signature` is the hex-encoded digest the caller sent, optionally
/// prefixed `sha256=` (the `X-Hub-Signature-256` convention). Returns `true` only
/// when the recomputed MAC matches, compared in CONSTANT TIME (`Mac::verify_slice`,
/// backed by the `subtle` crate). Fail-closed on EVERY error path — an empty secret,
/// a non-hex signature, or a wrong-length digest all yield `false`, never a panic
/// and never a partial/early-exit compare:
///
/// - An empty `secret` returns `false` unconditionally: a connection with no
///   configured webhook secret must never accept an inbound webhook (otherwise a
///   caller could authenticate with the HMAC of an empty key).
/// - A signature that is not valid lowercase/uppercase hex, or decodes to a length
///   other than 32 bytes, returns `false` (it can never equal a SHA-256 MAC).
pub fn verify_hmac_sha256(secret: &[u8], raw_body: &[u8], provided_signature: &str) -> bool {
    if secret.is_empty() {
        return false;
    }
    let hex_sig = provided_signature
        .strip_prefix("sha256=")
        .unwrap_or(provided_signature)
        .trim();
    let Ok(sig_bytes) = hex::decode(hex_sig) else {
        return false;
    };
    // HMAC accepts any key length, so new_from_slice only errs on an internal
    // invariant; treat any error as fail-closed rather than unwrapping.
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(raw_body);
    // verify_slice recomputes the MAC and compares in constant time; it also
    // rejects a wrong-length `sig_bytes` (not 32 bytes) without leaking length via
    // an early byte-by-byte compare.
    mac.verify_slice(&sig_bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Produce the correct lowercase-hex HMAC-SHA256 signature for a secret+body,
    /// so round-trip tests don't hand-hardcode digests.
    fn sign(secret: &[u8], body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn matches_published_rfc4231_vector() {
        // RFC 4231 Test Case 2: anchors the primitive to a published vector so a
        // future dependency swap that changed the algorithm would fail here.
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert!(verify_hmac_sha256(key, data, expected));
        // The X-Hub-Signature-256 "sha256=" prefix is accepted too.
        assert!(verify_hmac_sha256(key, data, &format!("sha256={expected}")));
    }

    #[test]
    fn valid_round_trip_signature_verifies() {
        let secret = b"super-secret-webhook-key";
        let body = br#"{"event":"incident.created","id":"INC0012345"}"#;
        assert!(verify_hmac_sha256(secret, body, &sign(secret, body)));
    }

    #[test]
    fn tampered_body_is_rejected() {
        let secret = b"super-secret-webhook-key";
        let body = br#"{"event":"incident.created","id":"INC0012345"}"#;
        let sig = sign(secret, body);
        let tampered = br#"{"event":"incident.created","id":"INC9999999"}"#;
        assert!(!verify_hmac_sha256(secret, tampered, &sig));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let secret = b"super-secret-webhook-key";
        let body = b"payload";
        let mut sig = sign(secret, body).into_bytes();
        // Flip the last hex nibble.
        let last = sig.last_mut().unwrap();
        *last = if *last == b'a' { b'b' } else { b'a' };
        let sig = String::from_utf8(sig).unwrap();
        assert!(!verify_hmac_sha256(secret, body, &sig));
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let body = b"payload";
        let sig = sign(b"the-real-secret", body);
        assert!(!verify_hmac_sha256(b"a-different-secret", body, &sig));
    }

    #[test]
    fn empty_secret_never_authenticates() {
        // Even a signature computed with an empty key must not authenticate — a
        // connection with no webhook secret configured rejects all inbound calls.
        let body = b"payload";
        let sig_with_empty_key = sign(b"", body);
        assert!(!verify_hmac_sha256(b"", body, &sig_with_empty_key));
    }

    #[test]
    fn malformed_or_wrong_length_signature_is_rejected() {
        let secret = b"super-secret-webhook-key";
        let body = b"payload";
        // Not hex at all.
        assert!(!verify_hmac_sha256(secret, body, "not-a-hex-signature"));
        // Valid hex but wrong length (not a 32-byte SHA-256 digest).
        assert!(!verify_hmac_sha256(secret, body, "deadbeef"));
        // Empty signature.
        assert!(!verify_hmac_sha256(secret, body, ""));
    }

    #[test]
    fn empty_body_with_valid_signature_verifies() {
        // An empty body is a legitimate message; its MAC must still verify.
        let secret = b"super-secret-webhook-key";
        assert!(verify_hmac_sha256(secret, b"", &sign(secret, b"")));
    }
}
