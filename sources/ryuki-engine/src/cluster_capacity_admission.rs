//! Cluster capacity ADMISSION engine (VMware placement).
//!
//! Turns the `cluster-capacity-admission` contract from a static descriptor into
//! a real admit / review / block / defer decision over the `cost_capacity`
//! inventory. PURE / dry-run: COMPUTE headroom (CPU + memory) is computed from
//! the VM utilization and drives the decision; datastore, vSAN, HA failover, DRS
//! balance, and reservation impact are REVIEWED in dry-run (no live vCenter
//! calls), matching the contract's review guards. `defer` is returned when the
//! cluster has no inventory to decide against.
//!
//! Honesty guards (admission is a placement GATE, so it must never under-count):
//! - used capacity is summed PER VM (`cores × util%`), not `total × mean(util%)`,
//!   so a small hot cluster of large VMs is not masked by idle ones;
//! - non-finite / out-of-range utilization fails CLOSED (treated as 100% used);
//! - a nonzero storage ask downgrades `admit` -> `review`, because storage
//!   headroom is only reviewed in dry-run, never admitted.

use crate::cost_capacity::VmUtilization;
use serde::Serialize;

/// Projected-utilization thresholds: at/over REVIEW the placement is tight
/// (review); at/over BLOCK, or when the ask does not fit at all, it is blocked.
const REVIEW_PCT: f64 = 80.0;
const BLOCK_PCT: f64 = 95.0;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum AdmissionDecision {
    Admit,
    Review,
    Block,
    Defer,
}

impl AdmissionDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Review => "review",
            Self::Block => "block",
            Self::Defer => "defer",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CapacitySignal {
    pub name: String,
    /// `ok` | `tight` | `exceeded` | `reviewed-dry-run` | `unknown`.
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AdmissionResult {
    pub decision: String,
    pub site: String,
    pub cluster: String,
    pub requested_cpu_cores: u32,
    pub requested_memory_gb: u32,
    pub requested_storage_gb: u32,
    /// `db` when decided against live inventory, `static-seed` when decided
    /// against canned demo inventory — so callers never mistake a seeded
    /// decision for a real one.
    pub inventory_source: String,
    pub signals: Vec<CapacitySignal>,
    pub reasons: Vec<String>,
}

/// Reviewed-in-dry-run signals the contract requires but for which there is no
/// live inventory (no datastore size, vSAN, HA, DRS, reservation, or freshness
/// telemetry). Names match `cluster-capacity-admission-contract.yaml`.
const DRY_RUN_SIGNALS: &[&str] = &[
    "datastore-headroom",
    "vsan-headroom",
    "ha-failover-headroom",
    "drs-balance",
    "reservation-impact",
    "stale-capacity-data",
];

/// Evaluate a placement request against a cluster's capacity. Returns the
/// contract's admit/review/block/defer decision driven by compute headroom, with
/// the remaining signals reviewed in dry-run. `inventory_source` records whether
/// `vms` came from the live DB (`"db"`) or the static seed (`"static-seed"`).
pub fn evaluate_cluster_admission(
    site: &str,
    cluster: &str,
    requested_cpu_cores: u32,
    requested_memory_gb: u32,
    requested_storage_gb: u32,
    vms: &[VmUtilization],
    inventory_source: &str,
) -> AdmissionResult {
    let cluster_vms: Vec<&VmUtilization> = vms
        .iter()
        .filter(|v| v.site == site && v.cluster == cluster)
        .collect();

    if cluster_vms.is_empty() {
        // No inventory for this cluster — cannot decide; defer to manual review.
        return AdmissionResult {
            decision: AdmissionDecision::Defer.as_str().into(),
            site: site.into(),
            cluster: cluster.into(),
            requested_cpu_cores,
            requested_memory_gb,
            requested_storage_gb,
            inventory_source: inventory_source.into(),
            signals: vec![
                unknown_signal("cpu-headroom", site, cluster),
                unknown_signal("memory-headroom", site, cluster),
            ],
            reasons: vec![format!(
                "Deferred — no capacity inventory to admit against for {site}/{cluster}"
            )],
        };
    }

    let total_cpu: u64 = cluster_vms.iter().map(|v| u64::from(v.cpu_cores)).sum();
    let total_mem: u64 = cluster_vms.iter().map(|v| u64::from(v.memory_gb)).sum();
    let used_cpu = used_capacity(&cluster_vms, |v| v.cpu_cores, |v| v.cpu_usage_pct);
    let used_mem = used_capacity(&cluster_vms, |v| v.memory_gb, |v| v.memory_usage_pct);

    let cpu_status = projected_status(used_cpu, f64::from(requested_cpu_cores), total_cpu as f64);
    let mem_status = projected_status(used_mem, f64::from(requested_memory_gb), total_mem as f64);

    // Decisions use exact `used` (above); only the human-facing signal detail is
    // rounded, so early rounding can never understate a threshold crossing.
    let used_cpu_display = used_cpu.round() as u64;
    let used_mem_display = used_mem.round() as u64;
    let mut signals = vec![
        CapacitySignal {
            name: "cpu-headroom".into(),
            status: cpu_status.as_label(),
            detail: format!(
                "CPU {used_cpu_display}/{total_cpu} cores used + requested {requested_cpu_cores}"
            ),
        },
        CapacitySignal {
            name: "memory-headroom".into(),
            status: mem_status.as_label(),
            detail: format!(
                "MEM {used_mem_display}/{total_mem} GB used + requested {requested_memory_gb}"
            ),
        },
    ];
    for name in DRY_RUN_SIGNALS {
        signals.push(CapacitySignal {
            name: (*name).into(),
            status: "reviewed-dry-run".into(),
            detail: format!("DRY-RUN: {name} reviewed (no live vCenter call)"),
        });
    }

    let compute_status = worst_status(cpu_status, mem_status);
    let (mut decision, reason) = match compute_status {
        Headroom::Exceeded => (
            AdmissionDecision::Block,
            "Blocked — compute headroom exceeded by the requested placement".to_string(),
        ),
        Headroom::Tight => (
            AdmissionDecision::Review,
            "Review — placement pushes compute utilization into the tight band".to_string(),
        ),
        Headroom::Ok => (
            AdmissionDecision::Admit,
            "Admit — sufficient compute headroom for the requested placement".to_string(),
        ),
    };
    let mut reasons = vec![reason];

    // Storage headroom is reviewed in dry-run only (no datastore telemetry), so a
    // nonzero storage ask must not ride out on a compute-only admit. Downgrade
    // admit -> review so callers never read "admit" as storage-verified.
    if requested_storage_gb > 0 && decision == AdmissionDecision::Admit {
        decision = AdmissionDecision::Review;
        reasons.push(
            "Review — requested storage is not verified in dry-run (datastore headroom reviewed, not admitted)"
                .to_string(),
        );
    }

    AdmissionResult {
        decision: decision.as_str().into(),
        site: site.into(),
        cluster: cluster.into(),
        requested_cpu_cores,
        requested_memory_gb,
        requested_storage_gb,
        inventory_source: inventory_source.into(),
        signals,
        reasons,
    }
}

fn unknown_signal(name: &str, site: &str, cluster: &str) -> CapacitySignal {
    CapacitySignal {
        name: name.into(),
        status: "unknown".into(),
        detail: format!("DRY-RUN: no capacity inventory for {site}/{cluster}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Headroom {
    Ok,
    Tight,
    Exceeded,
}

impl Headroom {
    fn as_label(self) -> String {
        match self {
            Self::Ok => "ok".into(),
            Self::Tight => "tight".into(),
            Self::Exceeded => "exceeded".into(),
        }
    }
}

/// Used capacity summed PER VM (`resource × util% / 100`), returned EXACT (not
/// rounded). This is the honest figure: unlike `total × mean(util%)` it cannot
/// be masked by idle VMs in a heterogeneous cluster, and keeping it unrounded
/// means a near-threshold utilization is never understated by early rounding
/// (e.g. used 9.41 on a 13-core cluster must not collapse to 9 before the 80%
/// check). Callers round only for display.
fn used_capacity(
    vms: &[&VmUtilization],
    resource: impl Fn(&VmUtilization) -> u32,
    pct: impl Fn(&VmUtilization) -> f64,
) -> f64 {
    vms.iter()
        .map(|v| f64::from(resource(v)) * sane_pct(pct(v)) / 100.0)
        .sum::<f64>()
}

/// Utilization percentages from inventory are constrained to a sane `[0, 100]`
/// band. Non-finite (NaN/inf) or out-of-range values FAIL CLOSED — treated as
/// 100% used — so a bad inventory row can never under-count usage and slip an
/// over-subscription past the gate.
fn sane_pct(pct: f64) -> f64 {
    if pct.is_finite() && (0.0..=100.0).contains(&pct) {
        pct
    } else {
        100.0
    }
}

fn projected_status(used: f64, requested: f64, total: f64) -> Headroom {
    if total <= 0.0 {
        return Headroom::Exceeded;
    }
    let projected = used + requested;
    let projected_pct = projected / total * 100.0;
    if !projected_pct.is_finite() {
        // Defensive: bad math fails closed rather than admitting.
        return Headroom::Exceeded;
    }
    if projected > total || projected_pct >= BLOCK_PCT {
        Headroom::Exceeded
    } else if projected_pct >= REVIEW_PCT {
        Headroom::Tight
    } else {
        Headroom::Ok
    }
}

fn worst_status(a: Headroom, b: Headroom) -> Headroom {
    match (a, b) {
        (Headroom::Exceeded, _) | (_, Headroom::Exceeded) => Headroom::Exceeded,
        (Headroom::Tight, _) | (_, Headroom::Tight) => Headroom::Tight,
        _ => Headroom::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(
        site: &str,
        cluster: &str,
        cpu: u32,
        mem: u32,
        cpu_pct: f64,
        mem_pct: f64,
    ) -> VmUtilization {
        VmUtilization {
            vm_name: format!("{cluster}-vm"),
            site: site.into(),
            cluster: cluster.into(),
            cpu_cores: cpu,
            memory_gb: mem,
            storage_gb: 100,
            cpu_usage_pct: cpu_pct,
            memory_usage_pct: mem_pct,
            monthly_cost: 0.0,
            idle: false,
            oversized: false,
            orphaned_disk_gb: 0,
        }
    }

    #[test]
    fn admit_when_ample_headroom() {
        // 100 cores at 10% used (10) + req 10 -> 20% projected -> ok; no storage.
        let vms = vec![vm("DEFRA", "c1", 100, 256, 10.0, 10.0)];
        let r = evaluate_cluster_admission("DEFRA", "c1", 10, 16, 0, &vms, "test");
        assert_eq!(r.decision, "admit");
        assert_eq!(r.inventory_source, "test");
        assert!(
            r.signals
                .iter()
                .any(|s| s.name == "cpu-headroom" && s.status == "ok")
        );
        // Two data-backed signals (cpu + memory) + the dry-run signals.
        assert_eq!(r.signals.len(), 2 + DRY_RUN_SIGNALS.len());
    }

    #[test]
    fn review_when_tight() {
        // 100 cores at 75% used (75) + req 10 -> 85% -> tight -> review.
        let vms = vec![vm("DEFRA", "c1", 100, 256, 75.0, 10.0)];
        let r = evaluate_cluster_admission("DEFRA", "c1", 10, 16, 0, &vms, "test");
        assert_eq!(r.decision, "review");
    }

    #[test]
    fn block_when_exceeded() {
        // 100 cores at 90% used (90) + req 20 -> 110% -> exceeded -> block.
        let vms = vec![vm("DEFRA", "c1", 100, 256, 90.0, 10.0)];
        let r = evaluate_cluster_admission("DEFRA", "c1", 20, 16, 0, &vms, "test");
        assert_eq!(r.decision, "block");
    }

    #[test]
    fn block_when_memory_exceeded_even_if_cpu_ok() {
        // CPU fine, memory 90% used (230/256) + req 64 -> exceeded -> block.
        let vms = vec![vm("DEFRA", "c1", 100, 256, 10.0, 90.0)];
        let r = evaluate_cluster_admission("DEFRA", "c1", 4, 64, 0, &vms, "test");
        assert_eq!(r.decision, "block");
    }

    #[test]
    fn defer_when_no_inventory() {
        let r = evaluate_cluster_admission("DEFRA", "ghost-cluster", 4, 8, 50, &[], "test");
        assert_eq!(r.decision, "defer");
        assert!(r.reasons[0].contains("Deferred"));
    }

    #[test]
    fn nonzero_storage_downgrades_admit_to_review() {
        // Compute is ample (admit), but a 500 GB storage ask is only reviewed in
        // dry-run, so the overall decision must not be a bare admit.
        let vms = vec![vm("DEFRA", "c1", 100, 256, 10.0, 10.0)];
        let r = evaluate_cluster_admission("DEFRA", "c1", 10, 16, 500, &vms, "test");
        assert_eq!(r.decision, "review");
        assert!(r.reasons.iter().any(|reason| reason.contains("storage")));
    }

    #[test]
    fn used_capacity_is_per_vm_not_mean_of_percentages() {
        // Regression: a hot 100-core VM (100%) + an idle 1-core VM (0%). Real CPU
        // used is 100 of 101 cores. A `total × mean(pct)` formula would report
        // ~51 used and ADMIT a 20-core ask; per-VM summing correctly blocks it.
        // Memory kept ample so the block is unambiguously CPU-driven.
        let vms = vec![
            vm("DEFRA", "c1", 100, 256, 100.0, 10.0),
            vm("DEFRA", "c1", 1, 4, 0.0, 0.0),
        ];
        let r = evaluate_cluster_admission("DEFRA", "c1", 20, 8, 0, &vms, "test");
        assert_eq!(r.decision, "block");
        assert!(
            r.signals
                .iter()
                .any(|s| s.name == "cpu-headroom" && s.status == "exceeded")
        );
    }

    #[test]
    fn decision_uses_exact_used_not_rounded_used() {
        // Regression for the 80% boundary: a 13-core cluster at 72.4% used = 9.412
        // cores. A 1-core ask projects to (9.412 + 1)/13 = 80.09% -> tight ->
        // review. If `used` were rounded to 9 first, it would read 76.9% and
        // wrongly admit. Memory kept ample so the boundary is CPU-driven.
        let vms = vec![vm("DEFRA", "c1", 13, 64, 72.4, 10.0)];
        let r = evaluate_cluster_admission("DEFRA", "c1", 1, 4, 0, &vms, "test");
        assert_eq!(r.decision, "review");
    }

    #[test]
    fn nonfinite_utilization_fails_closed() {
        // A NaN utilization row must not slip through as admit — it is treated as
        // 100% used (fail closed), so a near-full cluster blocks the ask.
        let vms = vec![vm("DEFRA", "c1", 100, 256, f64::NAN, 10.0)];
        let r = evaluate_cluster_admission("DEFRA", "c1", 8, 16, 0, &vms, "test");
        assert_eq!(r.decision, "block");
    }

    #[test]
    fn decision_values_match_contract() {
        // The four decisions the cluster-capacity-admission contract declares.
        for d in [
            AdmissionDecision::Admit,
            AdmissionDecision::Review,
            AdmissionDecision::Block,
            AdmissionDecision::Defer,
        ] {
            assert!(["admit", "review", "block", "defer"].contains(&d.as_str()));
        }
    }
}
