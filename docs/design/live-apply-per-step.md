# Live-apply per step (#42 follow-up)

Status: **design — awaiting owner review of the teardown state machine before slice B2 is built.**

This extends the multi-step orchestration engine (#42 slices 1–3, complete) so that
a request's steps can be applied to **real** infrastructure one at a time, each gated
by its own approval, instead of only orchestrated as `OfflineDryRun`.

## Owner decisions (2026-07-06)

1. **Failure mode = auto compensating teardown.** On a step's live-apply failure after
   earlier steps applied, automatically `terraform destroy` the applied steps in reverse
   dependency order.
2. **Grant binding = the dispatched step's `agent_job` id** (slice A, shipped `0620824`).
3. **Separation of duties = existing rule** (admin-gated, approver ≠ requester, site-scoped);
   the same operator may approve every step.
4. **Approval granularity = per-step, just-in-time.** Each step runs `LivePlan`, the operator
   reviews *that step's* real plan, then approves its apply. This is essentially forced:
   a downstream step's plan cannot be computed until its dependencies are really applied.

## Why this is bigger than a mode flag

The single-job live path is: one plan, approved once, applied once. Multi-step breaks two
assumptions:

- **Interleaving.** A step's plan depends on the *real applied state* of its dependencies,
  so plan → approve → apply must happen per step, in dependency order, not up front.
- **Partial application is real.** Once step A applies real infra and step B fails, there is
  real infrastructure to reconcile. The owner chose automatic compensating teardown, which
  means the system must also perform **destroy** operations — a destructive capability
  (overlapping the deferred #10 destroy mode) that needs the same signed-grant rigor as apply.

## Forward per-step state machine

Per step, driven in dependency order by the existing `ready_steps` core:

```
                deps all Applied
  Pending ─────────────────────────▶ Planning        (CP dispatches a LivePlan step job,
     │                                   │             step-bound; mode=LivePlan)
     │                                   │ agent returns plan + digest
     │                                   ▼
     │                             AwaitingApproval    (CP records the LivePlan digest;
     │                                   │             surfaced to approvers)
     │            operator POST .../steps/{key}/approve-live-apply
     │                                   │ (mints a step-scoped grant bound to a NEW
     │                                   │  LiveApply job id + the recorded digest)
     │                                   ▼
     │                                Applying          (CP dispatches the LiveApply step job)
     │                                   │ agent plan-then-apply: refuses if its replan
     │                                   │ digest ≠ grant digest (slice A integrity)
     │                     success ──────┼────── failure
     │                        ▼                     ▼
     │                    Applied                Failed ──▶ (request enters teardown)
     └───────────────────────┘
  All steps Applied ⇒ request → verifying
```

New step statuses beyond today's `Pending/Running/Succeeded/Failed`: `Planning`,
`AwaitingApproval`, `Applying`, `Applied` (live analogue of Succeeded), plus the teardown
states below. Dry-run orchestration (#42 2a/2b) keeps using the original four unchanged;
the live states are only reached when a request is executed in live mode.

## Auto compensating teardown state machine (the destructive part)

Triggered when any step's `LivePlan` or `LiveApply` fails while ≥1 step is already `Applied`.

```
  <step failure with prior Applied steps>
              │
              ▼
   request → TearingDown
              │
              │  for each Applied step, in REVERSE dependency order:
              ▼
        step → TearingDown ──▶ CP dispatches a LiveDestroy step job
              │                 (mode=LiveDestroy; authorized by that step's OWN
              │                  prior approval — approving apply authorized rollback;
              │                  bounded to what that step applied)
              │
     ┌────────┴─────────┐
     ▼                  ▼
  destroy ok        destroy FAILS
     │                  │
  step → ToreDown   STOP the cascade
     │                  │
     ▼                  ▼
  next applied     request → PartiallyAppliedNeedsOperator   (halt; no thrash;
  step in reverse                                             remaining Applied steps
     │                                                        left intact for the operator)
     ▼
  all Applied steps ToreDown ⇒ request → failed  (cleanly rolled back)
```

**Safety rails (non-negotiable):**

- A teardown of a step is authorized by **that step's own approval** — approving a step's
  apply also authorizes its later compensating rollback. No live destroy ever runs without
  a prior operator approval of that step.
- Teardown is **bounded** to the resources that step applied (its own workspace/state), never
  a blanket destroy.
- A teardown that **itself fails** stops the cascade and drops the request into a distinct
  `PartiallyAppliedNeedsOperator` state — never a retry loop, never a silent orphan. The
  applied-but-not-yet-torn-down steps are left intact and surfaced for manual remediation.
- `LiveDestroy` is a **new protocol mode** requiring agent-side destroy handling and its own
  trust gate (analogous to slice A's grant binding). It is off unless the agent is
  `--allow-live` with real credentials.

## Slice split

- **B1 — forward per-step live (CI-testable).** New step statuses + a `live_plan_digest`
  column; step LivePlan dispatch; the `AwaitingApproval` state; the
  `POST /api/requests/{id}/steps/{key}/approve-live-apply` endpoint that mints a step-scoped
  grant (slice A) + dispatches LiveApply; backlink verifies the step LiveApply result and
  advances. Replaces the slice-3 `HasStepPlan` guard with step-aware minting. Tested with
  simulated agent results (no real infra).
- **B2 — auto compensating teardown (CI-testable orchestration).** `LiveDestroy` mode; the
  reverse-order teardown cascade; the `PartiallyAppliedNeedsOperator` halt on teardown
  failure. CP orchestration + decision logic tested with simulated results.
- **C — real per-step apply/destroy (operator-only, not CI-validatable).** A deployed agent
  with `--allow-live`, real provider credentials, and a durable state backend actually
  planning/applying/destroying each step against real infrastructure. Delivered as an
  operator runbook; the owner validates it in their environment.

## Invariants carried from the existing live path

- Every live operation (apply and destroy) is authorized by a CP-signed, step-bound,
  short-TTL grant (slice A), verified independently by both the agent and the CP.
- Plan-then-apply integrity: the agent refuses to apply if its fresh replan digest diverges
  from the approved digest in the grant.
- Credentials never enter the control plane; the agent resolves them from its own host.
