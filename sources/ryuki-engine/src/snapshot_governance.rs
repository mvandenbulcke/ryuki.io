//! Snapshot governance evaluation (dry-run review).
//!
//! Turns the static `snapshot-governance` descriptor into a real engine: given a
//! proposed snapshot-exception request, it evaluates the contract's required
//! GUARDS (owner / expiry / backup-state / approval / lock / rollback / evidence
//! / CMDB-CI known) and emits the contract's SIGNALS, then decides
//! admit / review / block. The expiry/staleness logic is data-backed (the
//! requested expiry is parsed and compared against `now`, mirroring
//! `snapshot_engine::flag_stale_snapshots`).
//!
//! PURE / dry-run: no I/O, no live snapshot create/delete. `now` is passed in so
//! evaluation is deterministic and testable. Only redacted, aggregate governance
//! findings are produced — never VM names, raw inventory, or provider payloads.

use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;

/// A planned snapshot whose expiry falls within this many days of `now` is
/// flagged `expiry-due` (review) — past expiry is `stale-snapshot`.
const EXPIRY_DUE_DAYS: i64 = 7;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum SnapshotDecision {
    Admit,
    Review,
    Block,
}

impl SnapshotDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Review => "review",
            Self::Block => "block",
        }
    }
}

/// A proposed snapshot-governance request. Every field is optional; the engine
/// treats absence of a required field as a failed guard.
#[derive(Debug, Clone, Default)]
pub struct SnapshotGovernanceInput {
    pub ci_key: Option<String>,
    pub purpose: Option<String>,
    /// RFC3339 timestamp or `YYYY-MM-DD` date.
    pub requested_expiry: Option<String>,
    pub owner: Option<String>,
    /// e.g. `protected` / `pending` / `conflict`.
    pub backup_state: Option<String>,
    pub approval_route: Option<String>,
    pub lock_scope: Option<String>,
    pub rollback_notes: Option<String>,
    pub evidence_manifest: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GuardStatus {
    pub name: String,
    pub satisfied: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SnapshotSignal {
    pub name: String,
    /// `active` (the condition holds) | `clear` (checked, does not hold).
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SnapshotGovernanceResult {
    pub decision: String,
    pub guards: Vec<GuardStatus>,
    pub signals: Vec<SnapshotSignal>,
    pub blocked_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

/// Hard guards: each maps to a contract `blockedReason` and BLOCKS when its input
/// is absent. `cmdb-ci-known` is deliberately NOT here — the contract declares no
/// blockedReason for a missing CI, so it is a soft (review) signal instead.
const HARD_GUARDS: &[(&str, &str)] = &[
    ("owner-known", "missing-owner"),
    ("expiry-policy-known", "missing-expiry"),
    ("backup-state-known", "backup-conflict-unknown"),
    ("approval-route-assigned", "approval-missing"),
    ("lock-scope-defined", "lock-scope-missing"),
    ("rollback-notes-ready", "rollback-notes-missing"),
    ("evidence-redacted", "evidence-not-redacted"),
];

fn present(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|s| !s.trim().is_empty())
}

/// Parse a requested expiry as RFC3339, falling back to a `YYYY-MM-DD` date
/// (interpreted as 00:00:00 UTC). Returns `None` when absent or unparseable.
fn parse_expiry(value: &Option<String>) -> Option<DateTime<Utc>> {
    let raw = value.as_deref()?.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    let date = NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok()?;
    date.and_hms_opt(0, 0, 0)
        .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

/// Evaluate a proposed snapshot-governance request against the contract guards
/// and signals. `block` when any hard guard is unmet (it cannot proceed to
/// approval), `review` when all hard guards pass but a soft signal needs human
/// attention (stale / expiry-due / backup-conflict / unknown CI), `admit` when
/// every guard passes cleanly with no outstanding signal.
pub fn evaluate_snapshot_governance(
    input: &SnapshotGovernanceInput,
    now: DateTime<Utc>,
) -> SnapshotGovernanceResult {
    // The expiry guard requires a PARSEABLE expiry, not merely a present string.
    let expiry = parse_expiry(&input.requested_expiry);
    let guard_satisfied = |name: &str| -> bool {
        match name {
            "owner-known" => present(&input.owner),
            "expiry-policy-known" => expiry.is_some(),
            "backup-state-known" => present(&input.backup_state),
            "approval-route-assigned" => present(&input.approval_route),
            "lock-scope-defined" => present(&input.lock_scope),
            "rollback-notes-ready" => present(&input.rollback_notes),
            "evidence-redacted" => present(&input.evidence_manifest),
            "cmdb-ci-known" => present(&input.ci_key),
            _ => false,
        }
    };

    let mut guards = Vec::new();
    let mut blocked_reasons = Vec::new();
    for (name, reason) in HARD_GUARDS {
        let satisfied = guard_satisfied(name);
        guards.push(GuardStatus {
            name: (*name).into(),
            satisfied,
        });
        if !satisfied {
            blocked_reasons.push((*reason).into());
        }
    }
    // Soft guard (no blockedReason in the contract): CMDB CI.
    let ci_known = guard_satisfied("cmdb-ci-known");
    guards.push(GuardStatus {
        name: "cmdb-ci-known".into(),
        satisfied: ci_known,
    });

    // Signals (the contract's snapshotSignals that this engine can evaluate).
    // The `active` signals double as the review drivers below, so the review
    // decision is always explainable from the result (no "review with no cause").
    let mut signals = Vec::new();

    let signal = |signals: &mut Vec<SnapshotSignal>, name: &str, active: bool, detail: String| {
        signals.push(SnapshotSignal {
            name: name.into(),
            status: if active { "active" } else { "clear" }.into(),
            detail,
        });
    };

    // Expiry-driven signals (data-backed against `now`). `checked_add_signed`
    // keeps the public API panic-free for extreme `now` values (the handler
    // passes a real Utc::now(), but callers may pass any timestamp).
    let due_cutoff = now.checked_add_signed(chrono::Duration::days(EXPIRY_DUE_DAYS));
    match expiry {
        Some(exp) if exp <= now => {
            signal(
                &mut signals,
                "stale-snapshot",
                true,
                format!("requested expiry {} is at or before now", exp.to_rfc3339()),
            );
        }
        Some(exp) if due_cutoff.is_some_and(|cutoff| exp <= cutoff) => {
            signal(
                &mut signals,
                "expiry-due",
                true,
                format!(
                    "requested expiry {} is within {EXPIRY_DUE_DAYS} days",
                    exp.to_rfc3339()
                ),
            );
        }
        Some(exp) => {
            signal(
                &mut signals,
                "expiry-due",
                false,
                format!(
                    "requested expiry {} is beyond the review window",
                    exp.to_rfc3339()
                ),
            );
        }
        None => {
            // No parseable expiry — already a hard block via expiry-policy-known.
            signal(
                &mut signals,
                "expiry-due",
                false,
                "no parseable expiry supplied".into(),
            );
        }
    }

    let owner_unknown = !present(&input.owner);
    signal(
        &mut signals,
        "owner-unknown",
        owner_unknown,
        if owner_unknown {
            "no owner supplied".into()
        } else {
            "owner supplied".into()
        },
    );

    // Trim before comparing: a padded `" conflict "` still passes the present()
    // backup-state guard, so it must also be recognised as a conflict here.
    let backup_conflict = input
        .backup_state
        .as_deref()
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("conflict"));
    signal(
        &mut signals,
        "backup-conflict",
        backup_conflict,
        if backup_conflict {
            "backup state reports a conflict".into()
        } else {
            "no backup conflict reported".into()
        },
    );

    let planned_exception = input
        .purpose
        .as_deref()
        .is_some_and(|s| s.to_ascii_lowercase().contains("exception"));
    signal(
        &mut signals,
        "planned-exception",
        planned_exception,
        if planned_exception {
            "purpose is a planned snapshot exception".into()
        } else {
            "purpose is not flagged as an exception".into()
        },
    );

    // evidence-missing can only be active when the evidence-redacted HARD guard
    // also fails, which routes to `block` first — so it is informational here and
    // never the sole reason for a review.
    let evidence_missing = !present(&input.evidence_manifest);
    signal(
        &mut signals,
        "evidence-missing",
        evidence_missing,
        if evidence_missing {
            "no evidence manifest supplied".into()
        } else {
            "evidence manifest supplied".into()
        },
    );

    // Review drivers = every active signal, plus an unknown CMDB CI (a soft
    // condition the contract declares no blockedReason for). Deriving from the
    // emitted signals guarantees a `review` decision is always traceable to a
    // cause the caller can see in the result.
    let mut review_drivers: Vec<String> = signals
        .iter()
        .filter(|s| s.status == "active")
        .map(|s| s.name.clone())
        .collect();
    if !ci_known {
        review_drivers.push("cmdb-ci-known".into());
    }

    let (decision, reason) = if !blocked_reasons.is_empty() {
        (
            SnapshotDecision::Block,
            format!(
                "Blocked — {} required snapshot governance guard(s) unmet",
                blocked_reasons.len()
            ),
        )
    } else if !review_drivers.is_empty() {
        let mut reason = format!(
            "Review — escalated to human review: {}",
            review_drivers.join(", ")
        );
        // The catalog rule `stale-snapshot-requires-remediation-plan` is
        // decision:block, but the contract exposes no remediation-plan input and
        // no `remediation-plan-missing` blockedReason. In this dry-run subset the
        // rule is realised as escalation-to-review (a stale snapshot can never
        // auto-admit); a human supplies the owner + remediation plan downstream.
        if review_drivers.iter().any(|d| d == "stale-snapshot") {
            reason.push_str("; a stale snapshot requires owner + remediation plan before approval");
        }
        (SnapshotDecision::Review, reason)
    } else {
        (
            SnapshotDecision::Admit,
            "Admit — all snapshot governance guards satisfied with no outstanding signal"
                .to_string(),
        )
    };

    SnapshotGovernanceResult {
        decision: decision.as_str().into(),
        guards,
        signals,
        blocked_reasons,
        reasons: vec![reason],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-20T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// A fully-specified request with a far-future expiry, no conflict, and a
    /// non-exception purpose admits.
    fn complete_input() -> SnapshotGovernanceInput {
        SnapshotGovernanceInput {
            ci_key: Some("CI-1001".into()),
            purpose: Some("driver upgrade".into()),
            requested_expiry: Some("2026-12-01T00:00:00Z".into()),
            owner: Some("team-platform".into()),
            backup_state: Some("protected".into()),
            approval_route: Some("change-board".into()),
            lock_scope: Some("vm-only".into()),
            rollback_notes: Some("revert to snapshot".into()),
            evidence_manifest: Some("ev-123".into()),
        }
    }

    #[test]
    fn admits_complete_clean_request() {
        let r = evaluate_snapshot_governance(&complete_input(), now());
        assert_eq!(r.decision, "admit");
        assert!(r.blocked_reasons.is_empty());
        assert!(r.guards.iter().all(|g| g.satisfied));
    }

    #[test]
    fn blocks_when_required_guards_missing() {
        let input = SnapshotGovernanceInput {
            ci_key: Some("CI-1".into()),
            purpose: Some("p".into()),
            ..Default::default()
        };
        let r = evaluate_snapshot_governance(&input, now());
        assert_eq!(r.decision, "block");
        // owner/expiry/backup/approval/lock/rollback/evidence all missing.
        assert!(r.blocked_reasons.contains(&"missing-owner".to_string()));
        assert!(r.blocked_reasons.contains(&"missing-expiry".to_string()));
        assert!(
            r.blocked_reasons
                .contains(&"evidence-not-redacted".to_string())
        );
    }

    #[test]
    fn unparseable_expiry_fails_the_expiry_guard() {
        let mut input = complete_input();
        input.requested_expiry = Some("not-a-date".into());
        let r = evaluate_snapshot_governance(&input, now());
        assert_eq!(r.decision, "block");
        assert!(r.blocked_reasons.contains(&"missing-expiry".to_string()));
    }

    #[test]
    fn date_only_expiry_in_past_is_stale_review() {
        let mut input = complete_input();
        input.requested_expiry = Some("2026-01-01".into()); // before now (date-only)
        let r = evaluate_snapshot_governance(&input, now());
        assert_eq!(r.decision, "review");
        assert!(
            r.signals
                .iter()
                .any(|s| s.name == "stale-snapshot" && s.status == "active")
        );
    }

    #[test]
    fn expiry_within_window_is_review() {
        let mut input = complete_input();
        input.requested_expiry = Some("2026-06-24T00:00:00Z".into()); // 4 days out
        let r = evaluate_snapshot_governance(&input, now());
        assert_eq!(r.decision, "review");
        assert!(
            r.signals
                .iter()
                .any(|s| s.name == "expiry-due" && s.status == "active")
        );
    }

    #[test]
    fn backup_conflict_forces_review() {
        let mut input = complete_input();
        input.backup_state = Some("conflict".into());
        let r = evaluate_snapshot_governance(&input, now());
        assert_eq!(r.decision, "review");
        assert!(
            r.signals
                .iter()
                .any(|s| s.name == "backup-conflict" && s.status == "active")
        );
    }

    /// Regression: a padded backup state still passes the present() guard, so it
    /// must also be recognised as a conflict (not silently admitted).
    #[test]
    fn padded_backup_conflict_is_still_a_conflict() {
        let mut input = complete_input();
        input.backup_state = Some("  Conflict  ".into());
        let r = evaluate_snapshot_governance(&input, now());
        assert_eq!(r.decision, "review");
        assert!(
            r.signals
                .iter()
                .any(|s| s.name == "backup-conflict" && s.status == "active")
        );
    }

    #[test]
    fn unknown_ci_forces_review_but_does_not_block() {
        let mut input = complete_input();
        input.ci_key = None;
        let r = evaluate_snapshot_governance(&input, now());
        assert_eq!(r.decision, "review");
        // No blockedReason exists for a missing CI.
        assert!(r.blocked_reasons.is_empty());
        assert!(
            r.guards
                .iter()
                .any(|g| g.name == "cmdb-ci-known" && !g.satisfied)
        );
        // The review cause must be discoverable in the result, not opaque.
        assert!(
            r.reasons
                .iter()
                .any(|reason| reason.contains("cmdb-ci-known")),
            "review reason must name the driver: {:?}",
            r.reasons
        );
    }

    #[test]
    fn decision_values_match_contract() {
        for d in [
            SnapshotDecision::Admit,
            SnapshotDecision::Review,
            SnapshotDecision::Block,
        ] {
            assert!(["admit", "review", "block"].contains(&d.as_str()));
        }
    }
}
