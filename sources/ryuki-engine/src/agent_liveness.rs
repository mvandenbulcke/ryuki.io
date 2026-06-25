//! Pure agent-liveness classification (#44).
//!
//! An ENROLLED (approved) execution agent is expected to heartbeat. This
//! classifies an agent's OPERATIONAL liveness from its last heartbeat
//! (`last_seen_at`) — separately from its ENROLLMENT status (approved/revoked):
//! `online` (seen within the window) or `offline` (not seen within the window,
//! or never seen at all). Pure; the API supplies `last_seen` as unix seconds.

use serde::Serialize;

/// Operational liveness of one approved agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveness {
    /// Heartbeat seen within the liveness window.
    Online,
    /// No heartbeat within the window — or never seen.
    Offline,
}

impl AgentLiveness {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentLiveness::Online => "online",
            AgentLiveness::Offline => "offline",
        }
    }

    pub fn is_online(&self) -> bool {
        matches!(self, AgentLiveness::Online)
    }
}

/// Classify from the last-heartbeat instant (unix seconds; `None` ⇒ never seen
/// ⇒ `offline`). `offline_after_secs` is the liveness window. A last-seen in the
/// FUTURE (clock skew) is clamped to age 0 ⇒ `online`, never a negative age.
pub fn classify_agent_liveness(
    last_seen_unix: Option<i64>,
    now_unix: i64,
    offline_after_secs: i64,
) -> AgentLiveness {
    match last_seen_unix {
        None => AgentLiveness::Offline,
        Some(t) => {
            let age = now_unix.saturating_sub(t).max(0);
            if age > offline_after_secs {
                AgentLiveness::Offline
            } else {
                AgentLiveness::Online
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: i64 = 300; // 5 minutes

    #[test]
    fn never_seen_is_offline() {
        assert_eq!(
            classify_agent_liveness(None, 1_000_000, WINDOW),
            AgentLiveness::Offline
        );
    }

    #[test]
    fn recent_heartbeat_is_online() {
        let now = 1_000_000_000;
        assert_eq!(
            classify_agent_liveness(Some(now - 60), now, WINDOW),
            AgentLiveness::Online
        );
        assert!(AgentLiveness::Online.is_online());
    }

    #[test]
    fn stale_heartbeat_is_offline() {
        let now = 1_000_000_000;
        assert_eq!(
            classify_agent_liveness(Some(now - 1_000), now, WINDOW),
            AgentLiveness::Offline
        );
    }

    #[test]
    fn boundary_exactly_at_window_is_online() {
        let now = 1_000_000_000;
        // age == window is NOT > window, so still online.
        assert_eq!(
            classify_agent_liveness(Some(now - WINDOW), now, WINDOW),
            AgentLiveness::Online
        );
    }

    #[test]
    fn future_heartbeat_clamps_to_online() {
        let now = 1_000_000_000;
        assert_eq!(
            classify_agent_liveness(Some(now + 5_000), now, WINDOW),
            AgentLiveness::Online
        );
    }
}
