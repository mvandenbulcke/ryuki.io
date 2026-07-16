# Correctness/hardening swarm — 2026-06-30 (run 4)

A 6-finder bug-hunting sweep (validation / concurrency / error-handling / invariants / authz-secrets /
resource-cleanup) → 1 adversarial verifier per candidate (default verdict NOT-A-BUG unless the exact
triggering path is traced). 4 candidates → 3 CONFIRMED + fixed, 1 correctly REFUTED.

## Fixed
- ✅ **MAJOR — certificate `validity_days` DoS panic**: `validity_days: u32` was only checked `!= 0`,
  then flowed into `now + chrono::Duration::days(validity_days as i64)` which PANICS on `DateTime`
  overflow. An execute-tier caller POSTing `/api/maintain/certificates/request|renew` with
  `validityDays = 100000000` (up to u32::MAX) aborted the handler (no CatchPanicLayer → dropped
  request / 500 / scriptable DoS). FIX: cap at `MAX_CERTIFICATE_VALIDITY_DAYS = 36500` in
  `validate_certificate_request` (shared by request + /validate) and `renew_certificate` → the engine
  returns `Err` → the handlers map it to 400 (no panic). Tested no-panic for MAX+1 / 1e8 / u32::MAX.
- ✅ **MINOR — pagination `offset` 500**: `admin_platform_settings_history` did `params.offset
  .unwrap_or(0) as i64` (Option<usize>) — a huge `?offset=` wraps to a NEGATIVE i64, Postgres rejects
  (`OFFSET must not be negative`) → 500. FIX: `.min(i64::MAX as usize) as i64` (mirrors the `limit`
  clamp).
- ✅ **MINOR — `check_results` unbounded growth**: the hourly `synthetic_health_run` appends a
  `check_results` row per enabled health_check per tick, with NO prune (the run-3 sweep covered
  `job_executions` + `connection_health_checks` but missed this sibling). FIX: `PruneTarget::CheckResults`
  on the generalized prune + a `check_results_prune` job-kind (mig 133) running HOURLY (a daily cap of
  20000 only keeps up below ~833 checks; hourly → ~20000-check headroom) + a retention index.

## Refuted (adversarial verify caught — NOT a bug)
- **Multi-role approval quorum "unsatisfiable by two same-role approvers" + ON CONFLICT clobber**:
  NOT a bug. The `required_approval_roles >= 2` path is unreachable in production (the column defaults
  to 1; the only policy that raises it is explicitly deferred/design-only; the only n=2 setter is a
  test), AND a 2-role quorum being satisfiable by one DatacenterApprover + one PlatformAdmin (not two
  same-role admins) is the DOCUMENTED intended behavior (the threshold is capped at 2 because exactly
  two route roles exist). Fails closed; not a security bypass. Left as-is.

## Notes
- The `validity_days` cap is the only MAJOR — a real, scriptable, in-range-input handler panic any
  execute-tier principal could trigger; fixed at the validation boundary so every call path is safe.
- Bug 2's clamp is untested (a 1-line robustness fix; review did not block on the missing handler test).
