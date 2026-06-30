# run-7 analysis swarm — 2026-06-30

A discovery sweep angled at LESS-SWEPT surfaces (concurrency-races / input-validation-panics /
resilience-errors / schema-migration / protocol-contract / execution-agent-seam / portal-frontend),
each finder pipelined into a default-refute adversarial verifier.

## Run caveat (transient platform instability)
- First attempt: ALL 7 finders STALLED (no tool-call progress for 180s × 6 retries; 0 candidates,
  ~73 min wasted). A single narrow probe Explore agent run immediately afterward worked fine, so the
  stall was a transient platform/load blip, not a design issue. Hardened the script with an explicit
  READ-BUDGET rule (never Read contracts.rs/agents.rs/main.rs whole; rg → targeted <=400-line windows;
  ~25 tool-call cap) and re-ran.
- Second attempt: 5 of 7 finders + 2 verifiers failed with "Failed to authenticate. API Error: Access
  Notification" (transient auth blips). Only the **input-validation-panics** dimension completed →
  2 confirmed findings (below). The other dimensions (concurrency-races, resilience-errors,
  schema-migration, protocol-contract, execution-agent-seam, portal-frontend) did NOT complete and
  remain UN-SWEPT — a run-8 should re-run them when the platform is stable.

## Confirmed + shipped
- ✅ **IpamSubnetRow::to_engine() unchecked i32→unsigned casts (read path)** (contracts.rs ~29947).
  The READ path cast `self.vlan_id as u16` / `self.total_ips as u32` etc. raw, while the UPDATE
  handler already CLAMPs ("so a corrupt DB value cannot wrap") — a read/write asymmetry. A corrupt /
  out-of-band DB row (negative or out-of-range) would silently WRAP into a plausible-but-wrong API
  value (total_ips -1 → 4_294_967_295, misreporting capacity). Re-verified the nuance: vlan_id is
  CHECK-constrained since migration 099 (1..=4094) so its read cast is DEFENSE-IN-DEPTH/consistency;
  the IP counts have NO DB CHECK (migration 050 INTEGER NOT NULL, 099 didn't constrain them), so they
  are the genuine unguarded gap. FIX: mirror the write-path clamp in to_engine() — `vlan_id.clamp(1,
  4094)`, `total_ips/used_ips/available_ips.max(0)`. + pure unit test (corrupt → clamped, valid →
  unchanged). rg confirmed this was the ONLY `self.X as uN` read-path cast (no siblings). codex review
  pending.

## Not yet swept (run-8 — platform was unstable)
concurrency-races, resilience-errors, schema-migration, protocol-contract, execution-agent-seam,
portal-frontend. (A quick manual probe of scheduler.rs concurrency found only low-severity nuances —
a refresh-UPDATE that runs every scan, and a once-per-scan now_ms snapshot causing ≤1-interval
classification delay — neither compelling enough to action.)
