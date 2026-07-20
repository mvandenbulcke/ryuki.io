//! # ryuki-protocol
//!
//! Wire contract and Ed25519 signature primitives for the Ryuki execution-agent
//! ↔ control-plane protocol (design: docs/design/execution-agent.md §5–§6).
//!
//! **Pure types + crypto only.** No IO, no async, no network, no database.
//! This crate is shared by:
//! - `ryuki-api` (control plane — verifies agent signatures, signs approval grants)
//! - `ryuki-agent` (per-platform agent — signs results, verifies CP grants)
//!
//! ## Canonicalization guarantee
//!
//! All `signing_bytes` functions produce a **deterministic byte sequence** whose
//! canonical property is guaranteed by construction:
//!
//! 1. Fields are written in a **fixed, source-code-declared order** — there is
//!    no HashMap or BTreeMap involved in the signable set.
//! 2. Each field is **length-prefixed** (8-byte little-endian `u64` field length
//!    followed by the field bytes). This prevents ambiguity between, e.g., fields
//!    `"a"+"bc"` vs `"ab"+"c"`.
//! 3. There is **no JSON serialisation** in the signing path, so JSON field-ordering
//!    non-determinism cannot affect canonical bytes.
//! 4. A versioned, type-specific domain separator is prepended (for example,
//!    `b"ryuki-v5/signed-envelope"`) so signatures cannot be replayed across
//!    message types or canonical-layout revisions.
//!
//! The same function is always used by both the signer and the verifier.

pub mod crypto;
pub mod types;

pub use crypto::*;
pub use types::*;
