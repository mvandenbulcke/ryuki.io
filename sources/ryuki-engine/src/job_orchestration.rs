//! Multi-step orchestration (#42 slice 1) — the PURE dependency-readiness core.
//!
//! A request can decompose into multiple ORDERED steps, where a step may only be
//! dispatched once its prerequisite steps have SUCCEEDED. This module is the pure,
//! no-IO core that answers two questions with no scheduler / DB / agent-job
//! coupling, so the whole decision is unit-testable:
//!   1. `validate_plan` — is the step plan well-formed (unique keys, every
//!      dependency references a real step, no cycle)? A caller validates ONCE at
//!      plan time and rejects a malformed plan up front.
//!   2. `ready_steps` — given the current step statuses, which steps are READY to
//!      dispatch right now (Pending, and every dependency has Succeeded)?
//!
//! The wiring (a step/plan table + a dispatcher that creates one agent_job per
//! ready step, driven by the scheduler tick or the job-result ingest) is a
//! follow-up slice built on this core — the same engine-core-first shape as
//! `post_apply` / `drift_scan`.
//!
//! Semantics that matter:
//! - A dependent becomes ready ONLY once its prerequisite SUCCEEDS. A `Failed`
//!   prerequisite blocks every transitive dependent forever (they never become
//!   ready), so a multi-step request with a failed step STALLS rather than
//!   silently skipping the failed prerequisite — the caller fails the request.
//! - `ready_steps` is a single pass over each step's DIRECT dependencies (no graph
//!   traversal), so it cannot loop even on a cyclic graph — cycle members simply
//!   never become ready. Rejecting cycles is `validate_plan`'s job, done up front.
//! - Only `Pending` steps are ever returned, so an already-dispatched, running, or
//!   terminal step is never re-dispatched.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The readiness-relevant status of a single orchestration step, derived from its
/// backing agent_job (or `Pending` when no job has been dispatched for the step
/// yet). The many terminal-unsuccessful agent-job statuses (Failed/Expired/
/// DeadLettered/Cancelled/LiveRefused/ReconcileRequired) all collapse to `Failed`
/// here — for orchestration readiness they are equivalent: the prerequisite did
/// not succeed, so its dependents must not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// Not yet dispatched — a candidate to become ready once its deps succeed.
    Pending,
    /// Dispatched and in progress (leased/running) — neither a candidate nor terminal.
    Running,
    /// Completed successfully — satisfies dependents.
    Succeeded,
    /// Terminally unsuccessful — blocks every dependent forever.
    Failed,
}

/// One step in a request's orchestration plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// Stable per-plan step key (e.g. "provision", "configure"). Unique within a plan.
    pub key: String,
    /// Keys of the steps that must SUCCEED before this step may dispatch.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Current status of this step.
    pub status: StepStatus,
}

/// Why a step plan is malformed and must be rejected before any dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// Two steps share the same key — dependency references would be ambiguous.
    DuplicateStepKey(String),
    /// A step depends on a key that is not a step in the plan — the dependent could
    /// never become ready (fail-closed: a missing prerequisite never "succeeds").
    UnknownDependency { step: String, missing: String },
    /// The dependency graph contains a cycle (including a self-dependency) — the
    /// cycle members could never all succeed, so they would stall forever.
    DependencyCycle,
}

/// Validate a step plan is well-formed: unique keys, every `depends_on` references
/// a real step, and no dependency cycle. Pure; a caller runs this ONCE at plan
/// time and refuses a malformed plan rather than dispatching a request that can
/// never complete.
pub fn validate_plan(steps: &[Step]) -> Result<(), PlanError> {
    // Unique keys.
    let mut seen: HashMap<&str, ()> = HashMap::with_capacity(steps.len());
    for s in steps {
        if seen.insert(s.key.as_str(), ()).is_some() {
            return Err(PlanError::DuplicateStepKey(s.key.clone()));
        }
    }
    // Every dependency references a known step.
    for s in steps {
        for dep in &s.depends_on {
            if !seen.contains_key(dep.as_str()) {
                return Err(PlanError::UnknownDependency {
                    step: s.key.clone(),
                    missing: dep.clone(),
                });
            }
        }
    }
    // No cycle.
    if has_dependency_cycle(steps) {
        return Err(PlanError::DependencyCycle);
    }
    Ok(())
}

/// The keys of the steps that are READY to dispatch now: each is `Pending` and
/// every one of its dependencies exists in `steps` AND has status `Succeeded`.
///
/// Fail-closed: a dependency key that is not present, or that has not succeeded
/// (Pending/Running/Failed), leaves the dependent NOT ready; a step in a cycle is
/// never ready (its deps can never all be Succeeded). Only `Pending` steps are
/// returned, so a dispatched/terminal step is never re-dispatched. The returned
/// keys preserve the input order.
pub fn ready_steps(steps: &[Step]) -> Vec<String> {
    let status: HashMap<&str, StepStatus> =
        steps.iter().map(|s| (s.key.as_str(), s.status)).collect();
    steps
        .iter()
        .filter(|s| s.status == StepStatus::Pending)
        .filter(|s| {
            s.depends_on
                .iter()
                .all(|dep| status.get(dep.as_str()) == Some(&StepStatus::Succeeded))
        })
        .map(|s| s.key.clone())
        .collect()
}

/// Does the plan's dependency graph contain a cycle (including a self-dependency)?
/// Pure DFS with a three-colour visiting set; edges to unknown step keys are not
/// traversed (that is [`validate_plan`]'s `UnknownDependency` check, not a cycle).
pub fn has_dependency_cycle(steps: &[Step]) -> bool {
    let adj: HashMap<&str, &[String]> = steps
        .iter()
        .map(|s| (s.key.as_str(), s.depends_on.as_slice()))
        .collect();
    // 0 = unvisited (absent), 1 = on the current DFS stack, 2 = fully explored.
    let mut state: HashMap<&str, u8> = HashMap::with_capacity(steps.len());
    steps
        .iter()
        .any(|s| dfs_has_cycle(s.key.as_str(), &adj, &mut state))
}

fn dfs_has_cycle<'a>(
    node: &'a str,
    adj: &HashMap<&'a str, &'a [String]>,
    state: &mut HashMap<&'a str, u8>,
) -> bool {
    match state.get(node) {
        Some(1) => return true,  // back-edge to a node on the stack → cycle
        Some(2) => return false, // already fully explored, no cycle through here
        _ => {}
    }
    state.insert(node, 1);
    if let Some(deps) = adj.get(node) {
        for dep in deps.iter() {
            // Only follow edges to steps that actually exist in the plan.
            if adj.contains_key(dep.as_str()) && dfs_has_cycle(dep.as_str(), adj, state) {
                return true;
            }
        }
    }
    state.insert(node, 2);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(key: &str, deps: &[&str], status: StepStatus) -> Step {
        Step {
            key: key.to_string(),
            depends_on: deps.iter().map(|d| d.to_string()).collect(),
            status,
        }
    }

    #[test]
    fn no_deps_pending_step_is_ready() {
        let plan = vec![step("a", &[], StepStatus::Pending)];
        assert_eq!(ready_steps(&plan), vec!["a".to_string()]);
    }

    #[test]
    fn step_is_ready_only_when_all_deps_succeeded() {
        // b depends on a. a Pending → b not ready.
        let mut plan = vec![
            step("a", &[], StepStatus::Pending),
            step("b", &["a"], StepStatus::Pending),
        ];
        assert_eq!(ready_steps(&plan), vec!["a".to_string()], "only a is ready");

        // a Running → b still not ready.
        plan[0].status = StepStatus::Running;
        assert!(ready_steps(&plan).is_empty(), "a running, b blocked");

        // a Succeeded → b becomes ready (a no longer Pending, so not re-listed).
        plan[0].status = StepStatus::Succeeded;
        assert_eq!(ready_steps(&plan), vec!["b".to_string()]);
    }

    #[test]
    fn failed_dependency_blocks_dependent_forever() {
        // a Failed → b (depends on a) is never ready. It STALLS, not silently runs.
        let plan = vec![
            step("a", &[], StepStatus::Failed),
            step("b", &["a"], StepStatus::Pending),
        ];
        assert!(
            ready_steps(&plan).is_empty(),
            "a failed prerequisite must block the dependent"
        );
    }

    #[test]
    fn multiple_deps_need_all_succeeded() {
        // c depends on a AND b.
        let mut plan = vec![
            step("a", &[], StepStatus::Succeeded),
            step("b", &[], StepStatus::Running),
            step("c", &["a", "b"], StepStatus::Pending),
        ];
        assert!(ready_steps(&plan).is_empty(), "b not done → c blocked");
        plan[1].status = StepStatus::Succeeded;
        assert_eq!(ready_steps(&plan), vec!["c".to_string()]);
    }

    #[test]
    fn dispatched_or_terminal_steps_are_never_returned() {
        // Only Pending steps can be ready — Running/Succeeded/Failed never re-dispatch.
        let plan = vec![
            step("run", &[], StepStatus::Running),
            step("ok", &[], StepStatus::Succeeded),
            step("bad", &[], StepStatus::Failed),
        ];
        assert!(ready_steps(&plan).is_empty());
    }

    #[test]
    fn parallel_independent_steps_are_all_ready() {
        let plan = vec![
            step("a", &[], StepStatus::Pending),
            step("b", &[], StepStatus::Pending),
        ];
        assert_eq!(ready_steps(&plan), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn ready_steps_never_loops_on_a_cycle() {
        // a↔b cycle: neither can ever have all-deps-Succeeded, so neither is ready,
        // and ready_steps (no traversal) returns without looping.
        let plan = vec![
            step("a", &["b"], StepStatus::Pending),
            step("b", &["a"], StepStatus::Pending),
        ];
        assert!(ready_steps(&plan).is_empty());
    }

    #[test]
    fn validate_plan_accepts_a_well_formed_dag() {
        let plan = vec![
            step("a", &[], StepStatus::Pending),
            step("b", &["a"], StepStatus::Pending),
            step("c", &["a", "b"], StepStatus::Pending),
        ];
        assert_eq!(validate_plan(&plan), Ok(()));
    }

    #[test]
    fn validate_plan_rejects_duplicate_keys() {
        let plan = vec![
            step("a", &[], StepStatus::Pending),
            step("a", &[], StepStatus::Pending),
        ];
        assert_eq!(
            validate_plan(&plan),
            Err(PlanError::DuplicateStepKey("a".to_string()))
        );
    }

    #[test]
    fn validate_plan_rejects_unknown_dependency() {
        let plan = vec![step("b", &["a"], StepStatus::Pending)];
        assert_eq!(
            validate_plan(&plan),
            Err(PlanError::UnknownDependency {
                step: "b".to_string(),
                missing: "a".to_string(),
            })
        );
    }

    #[test]
    fn validate_plan_rejects_self_dependency_as_cycle() {
        let plan = vec![step("a", &["a"], StepStatus::Pending)];
        assert_eq!(validate_plan(&plan), Err(PlanError::DependencyCycle));
    }

    #[test]
    fn validate_plan_rejects_multi_node_cycle() {
        let plan = vec![
            step("a", &["c"], StepStatus::Pending),
            step("b", &["a"], StepStatus::Pending),
            step("c", &["b"], StepStatus::Pending),
        ];
        assert_eq!(validate_plan(&plan), Err(PlanError::DependencyCycle));
        assert!(has_dependency_cycle(&plan));
    }

    #[test]
    fn diamond_dependency_is_valid_and_orders_correctly() {
        //   a → b, a → c, (b,c) → d   (a classic diamond, no cycle)
        let mut plan = vec![
            step("a", &[], StepStatus::Succeeded),
            step("b", &["a"], StepStatus::Succeeded),
            step("c", &["a"], StepStatus::Running),
            step("d", &["b", "c"], StepStatus::Pending),
        ];
        assert_eq!(validate_plan(&plan), Ok(()));
        assert!(ready_steps(&plan).is_empty(), "c still running → d blocked");
        plan[2].status = StepStatus::Succeeded;
        assert_eq!(ready_steps(&plan), vec!["d".to_string()]);
    }
}
