//! Post-apply verification (missing-features #43) — the PURE decision core.
//!
//! After a `LiveApply` reports `Applied`, the intended state is only *asserted*,
//! not *confirmed*: a provider can silently reject or drift a change. Post-apply
//! verification re-plans the SAME configuration immediately after apply and reads
//! the result — a converged apply re-plans to **no changes**, so any pending
//! change means the apply did not fully take (drift), and the request must not be
//! marked `Verified`.
//!
//! This module is the pure, no-IO classifier over a `terraform plan` summary (or
//! an `ansible-playbook --check` summary). The runner produces that summary
//! today (`extract_plan_summary`); the CP/agent wiring that feeds it here and
//! transitions the job to `Verified` / emits a drift event is a thin follow-up
//! slice built on this core (the same engine-core-first shape as the `metric_*`
//! chain). Keeping the decision pure means it is fully unit-testable with no
//! live infrastructure.

use serde::{Deserialize, Serialize};

/// The outcome of comparing a post-apply re-plan against the "converged"
/// expectation (no pending changes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostApplyOutcome {
    /// The re-plan reports no pending changes — the apply fully converged.
    Verified,
    /// The re-plan still shows pending changes — the applied state does NOT match
    /// the intended configuration (drift or a partial/rejected apply).
    DriftDetected,
    /// The summary could not be classified (unexpected/empty output). Fail-closed:
    /// treated as NOT verified so a request is never marked `Verified` off an
    /// uninterpretable re-plan.
    Inconclusive,
}

impl PostApplyOutcome {
    /// Only a converged re-plan verifies the apply.
    pub fn is_verified(self) -> bool {
        matches!(self, PostApplyOutcome::Verified)
    }
}

/// Pending-change counts parsed from a terraform plan summary line
/// (`Plan: A to add, C to change, D to destroy.`). All zero ⇒ converged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanChangeCounts {
    pub add: u32,
    pub change: u32,
    pub destroy: u32,
}

impl PlanChangeCounts {
    pub fn total(self) -> u32 {
        self.add
            .saturating_add(self.change)
            .saturating_add(self.destroy)
    }
}

/// Domain-event type emitted when a live apply is confirmed converged.
pub const EVENT_POST_APPLY_VERIFIED: &str = "request.post-apply-verified";
/// Domain-event type emitted when a post-apply re-plan still shows pending
/// changes — an alert-worthy signal that the apply did not fully take.
pub const EVENT_POST_APPLY_DRIFT: &str = "request.post-apply-drift";

/// Parse the terraform "no changes" / "Plan: … to add, … to change, … to
/// destroy." summary the runner extracts. Returns `None` when the line is not a
/// recognizable terraform plan summary.
///
/// Recognizes (case-insensitively, trimmed, anywhere in the string):
/// - `No changes.` / `Your infrastructure matches the configuration` ⇒ all-zero.
/// - `Plan: <A> to add, <C> to change, <D> to destroy.` ⇒ the parsed counts.
/// - `Apply complete! Resources: <A> added, <C> changed, <D> destroyed.` is NOT a
///   plan line — post-apply verification runs a re-PLAN, not another apply — so it
///   is deliberately not matched here.
pub fn parse_plan_change_counts(summary: &str) -> Option<PlanChangeCounts> {
    let lower = summary.to_ascii_lowercase();
    if lower.contains("no changes") || lower.contains("infrastructure matches the configuration") {
        return Some(PlanChangeCounts {
            add: 0,
            change: 0,
            destroy: 0,
        });
    }
    // Find the "Plan:" summary and extract the three counts by their trailing verb.
    let plan_idx = lower.find("plan:")?;
    let tail = &lower[plan_idx..];
    let add = count_before(tail, "to add")?;
    let change = count_before(tail, "to change")?;
    let destroy = count_before(tail, "to destroy")?;
    Some(PlanChangeCounts {
        add,
        change,
        destroy,
    })
}

/// Extract the integer immediately preceding `verb` in `text` (e.g. the `2` in
/// `2 to add`). Scans the whitespace-separated token just before `verb`.
fn count_before(text: &str, verb: &str) -> Option<u32> {
    let pos = text.find(verb)?;
    // The token before the verb is the last whitespace-delimited run in text[..pos].
    let prefix = text[..pos].trim_end();
    let num = prefix.rsplit(|c: char| c.is_whitespace()).next()?;
    num.parse::<u32>().ok()
}

/// Classify a post-apply re-plan summary into a verification outcome.
///
/// A converged apply re-plans to zero pending changes ⇒ [`PostApplyOutcome::Verified`].
/// Any pending change ⇒ [`PostApplyOutcome::DriftDetected`]. An unparseable
/// summary ⇒ [`PostApplyOutcome::Inconclusive`] (fail-closed — never `Verified`).
pub fn classify_post_apply(replan_summary: &str) -> PostApplyOutcome {
    match parse_plan_change_counts(replan_summary) {
        Some(counts) if counts.total() == 0 => PostApplyOutcome::Verified,
        Some(_) => PostApplyOutcome::DriftDetected,
        None => PostApplyOutcome::Inconclusive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_changes_is_verified() {
        for s in [
            "No changes. Your infrastructure matches the configuration.",
            "no changes.",
            "...\nNo changes. Your infrastructure matches the configuration.\n...",
        ] {
            assert_eq!(classify_post_apply(s), PostApplyOutcome::Verified, "{s:?}");
        }
    }

    #[test]
    fn pending_changes_are_drift() {
        let s = "Plan: 2 to add, 1 to change, 0 to destroy.";
        assert_eq!(classify_post_apply(s), PostApplyOutcome::DriftDetected);
        let counts = parse_plan_change_counts(s).unwrap();
        assert_eq!(counts.total(), 3);
        assert_eq!(counts.add, 2);
        assert_eq!(counts.change, 1);
        assert_eq!(counts.destroy, 0);
    }

    #[test]
    fn a_pure_destroy_replan_is_drift() {
        // A re-plan that wants to destroy something means the applied resource is
        // unexpectedly present / not converged.
        let s = "Plan: 0 to add, 0 to change, 3 to destroy.";
        assert_eq!(classify_post_apply(s), PostApplyOutcome::DriftDetected);
        assert_eq!(parse_plan_change_counts(s).unwrap().total(), 3);
    }

    #[test]
    fn all_zero_plan_line_is_verified() {
        // Some terraform versions emit the explicit zero triple rather than "No changes".
        let s = "Plan: 0 to add, 0 to change, 0 to destroy.";
        assert_eq!(classify_post_apply(s), PostApplyOutcome::Verified);
    }

    #[test]
    fn unparseable_summary_is_inconclusive_not_verified() {
        for s in [
            "",
            "terraform initialized",
            "Error: something went wrong",
            "Apply complete! Resources: 2 added, 0 changed, 0 destroyed.",
        ] {
            let outcome = classify_post_apply(s);
            assert_eq!(outcome, PostApplyOutcome::Inconclusive, "{s:?}");
            assert!(!outcome.is_verified(), "must never verify off {s:?}");
        }
    }

    #[test]
    fn is_verified_only_for_verified() {
        assert!(PostApplyOutcome::Verified.is_verified());
        assert!(!PostApplyOutcome::DriftDetected.is_verified());
        assert!(!PostApplyOutcome::Inconclusive.is_verified());
    }

    #[test]
    fn total_saturates_and_counts_survive_extra_whitespace() {
        // The runner's summary can carry odd spacing; the token-before-verb parse
        // must still pick the right integer.
        let s = "Plan:  10   to add,   0 to change,   5 to destroy.";
        let c = parse_plan_change_counts(s).unwrap();
        assert_eq!((c.add, c.change, c.destroy), (10, 0, 5));
        assert_eq!(c.total(), 15);
    }
}
