//! Pure circuit-breaker state machine for guarding flaky provider/adapter calls
//! (#30).
//!
//! A breaker shields the platform from hammering a failing dependency: after
//! enough consecutive failures it OPENS and rejects calls for a cooldown, then
//! allows a single HALF-OPEN probe; the probe's outcome either CLOSES it (back
//! to normal) or re-OPENS it. This module is pure and deterministic — the caller
//! supplies "now" (unix seconds), records each real call outcome, and persists
//! the returned [`Breaker`]. No IO, no clock access.
//!
//! Protocol: call [`allow`] before each attempt; only attempt when it returns
//! `true`; then feed the real outcome to [`record`]. Because `allow` flips an
//! elapsed `Open` to `HalfOpen`, `record` normally sees `Closed`/`HalfOpen`.

use serde::{Deserialize, Serialize};

/// The three classic breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    /// Calls flow normally; failures are counted.
    Closed,
    /// Calls are rejected until the cooldown elapses.
    Open,
    /// A single probe is allowed to test recovery.
    HalfOpen,
}

impl BreakerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            BreakerState::Closed => "closed",
            BreakerState::Open => "open",
            BreakerState::HalfOpen => "half_open",
        }
    }
}

/// Tunables for a breaker. All breakers in this MVP share [`BreakerConfig::DEFAULT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerConfig {
    /// Consecutive failures in `Closed` that trip it `Open`.
    pub failure_threshold: u32,
    /// Consecutive successes in `HalfOpen` that close it.
    pub success_threshold: u32,
    /// Seconds a breaker stays `Open` before a `HalfOpen` probe is allowed.
    pub cooldown_secs: i64,
}

impl BreakerConfig {
    pub const DEFAULT: BreakerConfig = BreakerConfig {
        failure_threshold: 5,
        success_threshold: 2,
        cooldown_secs: 30,
    };

    /// A config is usable only with positive thresholds and a non-negative
    /// cooldown — a zero threshold would trip/close on no evidence.
    pub fn validate(&self) -> Result<(), String> {
        if self.failure_threshold < 1 {
            return Err("failure_threshold must be >= 1".into());
        }
        if self.success_threshold < 1 {
            return Err("success_threshold must be >= 1".into());
        }
        if self.cooldown_secs < 0 {
            return Err("cooldown_secs must be >= 0".into());
        }
        Ok(())
    }
}

/// The persisted breaker state for one guarded dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Breaker {
    pub state: BreakerState,
    /// Consecutive failures while `Closed` (reset on any success).
    pub consecutive_failures: u32,
    /// Consecutive successes while `HalfOpen` (reset on any failure / on close).
    pub consecutive_successes: u32,
    /// Unix seconds when it last entered `Open` (drives the cooldown). `None`
    /// whenever the state is not `Open`.
    pub opened_at_unix: Option<i64>,
}

impl Breaker {
    /// A fresh, healthy breaker.
    pub fn closed() -> Self {
        Breaker {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            opened_at_unix: None,
        }
    }
}

impl Default for Breaker {
    fn default() -> Self {
        Breaker::closed()
    }
}

/// Seconds remaining before an `Open` breaker permits a probe. Clamped to
/// `[0, cooldown_secs]`: `0` once due (and for non-`Open` states), never
/// negative, and never longer than the configured cooldown even if the clock
/// runs backwards (`now < opened_at` ⇒ elapsed treated as `0`).
pub fn cooldown_remaining_secs(breaker: &Breaker, cfg: &BreakerConfig, now_unix: i64) -> i64 {
    if breaker.state != BreakerState::Open {
        return 0;
    }
    let opened = breaker.opened_at_unix.unwrap_or(now_unix);
    // saturating_sub avoids i64 overflow on extreme inputs; .max(0) clamps a
    // backwards clock so the wait can never EXCEED the configured cooldown.
    let elapsed = now_unix.saturating_sub(opened).max(0);
    (cfg.cooldown_secs - elapsed).max(0)
}

/// Decide whether a call may proceed NOW, returning the (possibly transitioned)
/// breaker. An `Open` breaker whose cooldown has elapsed transitions to
/// `HalfOpen` and allows one probe. The caller MUST persist the returned breaker
/// and, if `true`, record the outcome via [`record`].
pub fn allow(breaker: &Breaker, cfg: &BreakerConfig, now_unix: i64) -> (bool, Breaker) {
    match breaker.state {
        BreakerState::Closed | BreakerState::HalfOpen => (true, breaker.clone()),
        BreakerState::Open => {
            if cooldown_remaining_secs(breaker, cfg, now_unix) == 0 {
                let mut next = breaker.clone();
                next.state = BreakerState::HalfOpen;
                next.consecutive_successes = 0;
                next.opened_at_unix = None;
                (true, next)
            } else {
                (false, breaker.clone())
            }
        }
    }
}

/// Fold a single real call outcome into the breaker, returning the new state.
///
/// - `Closed` + failure: increment; trip `Open` at `failure_threshold`.
/// - `Closed` + success: reset the failure run.
/// - `HalfOpen` + success: increment; `Closed` at `success_threshold`.
/// - `HalfOpen` + failure: back to `Open` immediately.
/// - `Open` (a straggler recorded without a fresh [`allow`]): a failure refreshes
///   the cooldown; a success is ignored (recovery must go through a `HalfOpen`
///   probe, never a stray success while open).
pub fn record(breaker: &Breaker, cfg: &BreakerConfig, success: bool, now_unix: i64) -> Breaker {
    let mut b = breaker.clone();
    match (b.state, success) {
        (BreakerState::Closed, true) => {
            b.consecutive_failures = 0;
        }
        (BreakerState::Closed, false) => {
            b.consecutive_failures = b.consecutive_failures.saturating_add(1);
            if b.consecutive_failures >= cfg.failure_threshold {
                trip_open(&mut b, now_unix);
            }
        }
        (BreakerState::HalfOpen, true) => {
            b.consecutive_successes = b.consecutive_successes.saturating_add(1);
            if b.consecutive_successes >= cfg.success_threshold {
                b.state = BreakerState::Closed;
                b.consecutive_failures = 0;
                b.consecutive_successes = 0;
                b.opened_at_unix = None;
            }
        }
        (BreakerState::HalfOpen, false) => {
            trip_open(&mut b, now_unix);
        }
        (BreakerState::Open, false) => {
            // A failed straggler: refresh the cooldown so we keep backing off.
            b.opened_at_unix = Some(now_unix);
        }
        (BreakerState::Open, true) => {
            // A stray success while open does NOT close the breaker.
        }
    }
    b
}

fn trip_open(b: &mut Breaker, now_unix: i64) {
    b.state = BreakerState::Open;
    b.opened_at_unix = Some(now_unix);
    b.consecutive_successes = 0;
}

/// Force a breaker back to a healthy `Closed` (operator override).
pub fn reset() -> Breaker {
    Breaker::closed()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: BreakerConfig = BreakerConfig {
        failure_threshold: 3,
        success_threshold: 2,
        cooldown_secs: 30,
    };

    #[test]
    fn default_config_is_valid() {
        assert!(BreakerConfig::DEFAULT.validate().is_ok());
    }

    #[test]
    fn zero_thresholds_rejected() {
        let bad = BreakerConfig {
            failure_threshold: 0,
            ..CFG
        };
        assert!(bad.validate().is_err());
        let bad = BreakerConfig {
            success_threshold: 0,
            ..CFG
        };
        assert!(bad.validate().is_err());
        let bad = BreakerConfig {
            cooldown_secs: -1,
            ..CFG
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn closed_trips_open_after_threshold_failures() {
        let mut b = Breaker::closed();
        for _ in 0..(CFG.failure_threshold - 1) {
            b = record(&b, &CFG, false, 100);
            assert_eq!(
                b.state,
                BreakerState::Closed,
                "below threshold stays closed"
            );
        }
        b = record(&b, &CFG, false, 100);
        assert_eq!(b.state, BreakerState::Open, "threshold failure trips open");
        assert_eq!(b.opened_at_unix, Some(100));
    }

    #[test]
    fn success_resets_failure_run() {
        let mut b = Breaker::closed();
        b = record(&b, &CFG, false, 1);
        b = record(&b, &CFG, false, 2);
        assert_eq!(b.consecutive_failures, 2);
        b = record(&b, &CFG, true, 3);
        assert_eq!(
            b.consecutive_failures, 0,
            "a success clears the failure run"
        );
        assert_eq!(b.state, BreakerState::Closed);
    }

    #[test]
    fn open_rejects_until_cooldown_then_half_opens() {
        let mut b = Breaker::closed();
        for _ in 0..CFG.failure_threshold {
            b = record(&b, &CFG, false, 100);
        }
        assert_eq!(b.state, BreakerState::Open);

        // Within cooldown: rejected, stays open.
        let (allowed, b_mid) = allow(&b, &CFG, 100 + CFG.cooldown_secs - 1);
        assert!(!allowed);
        assert_eq!(b_mid.state, BreakerState::Open);
        assert_eq!(
            cooldown_remaining_secs(&b, &CFG, 100 + CFG.cooldown_secs - 1),
            1
        );

        // At cooldown: a probe is allowed and it half-opens.
        let (allowed, b_probe) = allow(&b, &CFG, 100 + CFG.cooldown_secs);
        assert!(allowed);
        assert_eq!(b_probe.state, BreakerState::HalfOpen);
        assert_eq!(b_probe.opened_at_unix, None);
    }

    #[test]
    fn gated_recovery_closes_after_cooldown() {
        // Mirrors the API record handler: allow() advances Open->HalfOpen once the
        // cooldown elapses, then record() folds the probe outcome. Without the
        // allow() gate, record(Open, success) would ignore the probe and the
        // breaker could never recover.
        let mut b = Breaker::closed();
        for _ in 0..CFG.failure_threshold {
            b = record(&b, &CFG, false, 100);
        }
        assert_eq!(b.state, BreakerState::Open);

        let base = 100 + CFG.cooldown_secs;
        for i in 0..CFG.success_threshold {
            let now = base + i as i64;
            let (allowed, gated) = allow(&b, &CFG, now);
            assert!(allowed, "cooldown elapsed -> a probe is allowed");
            b = record(&gated, &CFG, true, now);
        }
        assert_eq!(
            b.state,
            BreakerState::Closed,
            "gated probes close the breaker"
        );
        assert_eq!(b.opened_at_unix, None);
    }

    #[test]
    fn half_open_closes_after_success_threshold() {
        let mut b = Breaker {
            state: BreakerState::HalfOpen,
            consecutive_failures: 0,
            consecutive_successes: 0,
            opened_at_unix: None,
        };
        b = record(&b, &CFG, true, 200);
        assert_eq!(
            b.state,
            BreakerState::HalfOpen,
            "one success not yet enough"
        );
        b = record(&b, &CFG, true, 201);
        assert_eq!(b.state, BreakerState::Closed, "second success closes");
        assert_eq!(b.consecutive_failures, 0);
    }

    #[test]
    fn half_open_failure_reopens_immediately() {
        let b = Breaker {
            state: BreakerState::HalfOpen,
            consecutive_failures: 0,
            consecutive_successes: 1,
            opened_at_unix: None,
        };
        let b = record(&b, &CFG, false, 300);
        assert_eq!(b.state, BreakerState::Open);
        assert_eq!(b.opened_at_unix, Some(300));
        assert_eq!(b.consecutive_successes, 0);
    }

    #[test]
    fn stray_success_while_open_does_not_close() {
        let b = Breaker {
            state: BreakerState::Open,
            consecutive_failures: 3,
            consecutive_successes: 0,
            opened_at_unix: Some(100),
        };
        let b = record(&b, &CFG, true, 105);
        assert_eq!(
            b.state,
            BreakerState::Open,
            "recovery requires a half-open probe"
        );
        assert_eq!(
            b.opened_at_unix,
            Some(100),
            "timer not refreshed by a success"
        );
    }

    #[test]
    fn failed_straggler_while_open_refreshes_cooldown() {
        let b = Breaker {
            state: BreakerState::Open,
            consecutive_failures: 3,
            consecutive_successes: 0,
            opened_at_unix: Some(100),
        };
        let b = record(&b, &CFG, false, 120);
        assert_eq!(b.state, BreakerState::Open);
        assert_eq!(b.opened_at_unix, Some(120), "failure backs off again");
    }

    #[test]
    fn cooldown_remaining_clamped_to_range() {
        let b = Breaker {
            state: BreakerState::Open,
            consecutive_failures: 3,
            consecutive_successes: 0,
            opened_at_unix: Some(100),
        };
        // Past the cooldown -> 0 (never negative).
        assert_eq!(cooldown_remaining_secs(&b, &CFG, 10_000), 0);
        // A backwards clock (now < opened_at) never EXCEEDS the configured
        // cooldown — elapsed is clamped to 0, so the full cooldown remains.
        assert_eq!(cooldown_remaining_secs(&b, &CFG, 50), CFG.cooldown_secs);
        // Mid-cooldown is exact.
        assert_eq!(
            cooldown_remaining_secs(&b, &CFG, 110),
            CFG.cooldown_secs - 10
        );
    }
}
