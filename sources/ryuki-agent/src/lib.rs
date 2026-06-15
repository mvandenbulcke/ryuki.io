//! ryuki-agent — library facade.
//!
//! Exposes the agent's core modules as a public crate so integration tests
//! in other workspace members (e.g. `ryuki-api`) can call agent code directly
//! without going over the network.
//!
//! ## Module visibility
//!
//! Every module is `pub` so external callers can reach the types they need.
//! The binary (`main.rs`) re-exports via this lib rather than declaring its
//! own `mod` statements, keeping the two compilation units in sync.

pub mod client;
pub mod config;
pub mod executor;
pub mod identity;
pub mod live;
pub mod live_exec;
pub mod outbox;
pub mod result;
pub mod run;
