use serde::Serialize;
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize)]
struct VmUtilization {
    vm_name: String,
    site: String,
    cluster: String,
    cpu_cores: u32,
    memory_gb: u32,
    storage_gb: u32,
    cpu_usage_pct: f64,
    memory_usage_pct: f64,
    monthly_cost: f64,
    idle: bool,
    oversized: bool,
    orphaned_disk_gb: u32,
}

#[derive(Debug, Clone)]
struct PricingConfig {
    cost_per_core: f64,
    cost_per_gb_ram: f64,
    cost_per_gb_storage: f64,
    license_cost_per_vm: f64,
}

type CostCapacityStore = (Vec<VmUtilization>, PricingConfig);

static COST_STORE: OnceLock<Mutex<CostCapacityStore>> = OnceLock::new();

fn cost_store() -> &'static Mutex<CostCapacityStore> {
    COST_STORE.get_or_init(|| Mutex::new(seed_data()))
}

fn seed_data() -> CostCapacityStore {
    let pricing = PricingConfig {
        cost_per_core: 12.50,
        cost_per_gb_ram: 3.20,
        cost_per_gb_storage: 0.08,
        license_cost_per_vm: 45.00,
    };

    let mut vms = Vec::new();

    #[allow(clippy::type_complexity)]
    let sites: [(&str, &[(&str, u32, u32, u32, f64, f64, bool, bool, u32)]); 2] = [
        (
            "DEFRA",
            &[
                ("defra-srv-01", 8, 32, 200, 72.5, 65.0, false, false, 0),
                ("defra-srv-02", 4, 16, 100, 18.2, 22.1, false, false, 0),
                ("defra-srv-03", 16, 64, 500, 85.3, 78.0, false, false, 0),
                ("defra-db-01", 12, 48, 400, 91.2, 88.5, false, false, 0),
                ("defra-web-01", 2, 8, 80, 12.0, 35.0, false, true, 0),
                ("defra-web-02", 2, 8, 80, 14.0, 31.0, false, true, 0),
                ("defra-dev-01", 4, 16, 100, 2.1, 5.3, true, false, 0),
                ("defra-dev-02", 4, 16, 120, 3.5, 6.2, true, false, 50),
                ("defra-legacy-01", 2, 4, 60, 95.0, 92.0, false, false, 0),
                ("defra-dc-01", 4, 16, 100, 45.0, 48.0, false, false, 0),
            ],
        ),
        (
            "GBLON",
            &[
                ("gblon-srv-01", 8, 32, 200, 68.0, 60.0, false, false, 0),
                ("gblon-srv-02", 4, 16, 100, 22.0, 28.0, false, false, 0),
                ("gblon-srv-03", 16, 64, 500, 80.0, 75.0, false, false, 0),
                ("gblon-db-01", 12, 48, 400, 88.0, 82.0, false, false, 0),
                ("gblon-dr-01", 8, 32, 300, 3.0, 4.5, true, false, 0),
                ("gblon-web-01", 2, 8, 60, 18.0, 42.0, false, true, 0),
                ("gblon-qa-01", 4, 16, 100, 4.0, 7.0, true, false, 0),
                ("gblon-qa-02", 8, 32, 200, 5.0, 8.5, true, true, 100),
            ],
        ),
    ];

    for (site, site_vms) in &sites {
        for &(name, cpu, mem, storage, cpu_pct, mem_pct, idle, oversized, orphaned_disk) in
            site_vms.iter()
        {
            let cluster = if name.contains("db") {
                format!("{}-db-cluster", site.to_lowercase())
            } else if name.contains("web") {
                format!("{}-web-cluster", site.to_lowercase())
            } else if name.contains("dr") {
                format!("{}-dr-cluster", site.to_lowercase())
            } else {
                format!("{}-general-cluster", site.to_lowercase())
            };

            let compute_cost = cpu as f64 * pricing.cost_per_core;
            let ram_cost = mem as f64 * pricing.cost_per_gb_ram;
            let storage_cost = storage as f64 * pricing.cost_per_gb_storage;
            let license = pricing.license_cost_per_vm;
            let monthly_cost = compute_cost + ram_cost + storage_cost + license;

            vms.push(VmUtilization {
                vm_name: name.to_string(),
                site: site.to_string(),
                cluster,
                cpu_cores: cpu,
                memory_gb: mem,
                storage_gb: storage,
                cpu_usage_pct: cpu_pct,
                memory_usage_pct: mem_pct,
                monthly_cost,
                idle,
                oversized,
                orphaned_disk_gb: orphaned_disk,
            });
        }
    }

    (vms, pricing)
}

pub fn get_site_capacity(site: &str) -> Result<Value, String> {
    let store = cost_store().lock().map_err(|e| e.to_string())?;
    let vms: Vec<&VmUtilization> = store.0.iter().filter(|v| v.site == site).collect();

    if vms.is_empty() {
        return Err(format!("Site '{}' not found", site));
    }

    let total_cpu: u32 = vms.iter().map(|v| v.cpu_cores).sum();
    let total_mem: u32 = vms.iter().map(|v| v.memory_gb).sum();
    let total_storage: u32 = vms.iter().map(|v| v.storage_gb).sum();

    let used_cpu = (total_cpu as f64 * vms.iter().map(|v| v.cpu_usage_pct).sum::<f64>()
        / (vms.len() as f64 * 100.0))
        .round() as u32;
    let used_mem = (total_mem as f64 * vms.iter().map(|v| v.memory_usage_pct).sum::<f64>()
        / (vms.len() as f64 * 100.0))
        .round() as u32;
    let used_storage = total_storage; // storage is allocated, not dynamic

    let cpu_util = vms.iter().map(|v| v.cpu_usage_pct).sum::<f64>() / vms.len() as f64;
    let mem_util = vms.iter().map(|v| v.memory_usage_pct).sum::<f64>() / vms.len() as f64;

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "total_cpu_cores": total_cpu,
        "used_cpu_cores": used_cpu,
        "total_memory_gb": total_mem,
        "used_memory_gb": used_mem,
        "total_storage_gb": total_storage,
        "used_storage_gb": used_storage,
        "vm_count": vms.len(),
        "cpu_utilization_pct": (cpu_util * 10.0).round() / 10.0,
        "memory_utilization_pct": (mem_util * 10.0).round() / 10.0,
        "clusters": cluster_summary(site, &vms)
    }))
}

fn cluster_summary(_site: &str, vms: &[&VmUtilization]) -> Value {
    use std::collections::HashMap;
    let mut clusters: HashMap<&str, Vec<&&VmUtilization>> = HashMap::new();
    for vm in vms {
        clusters.entry(vm.cluster.as_str()).or_default().push(vm);
    }
    let summaries: Vec<Value> = clusters
        .iter()
        .map(|(name, cluster_vms)| {
            let total_cpu: u32 = cluster_vms.iter().map(|v| v.cpu_cores).sum();
            let total_mem: u32 = cluster_vms.iter().map(|v| v.memory_gb).sum();
            let cpu_util =
                cluster_vms.iter().map(|v| v.cpu_usage_pct).sum::<f64>() / cluster_vms.len() as f64;
            let mem_util = cluster_vms.iter().map(|v| v.memory_usage_pct).sum::<f64>()
                / cluster_vms.len() as f64;
            json!({
                "cluster_name": name,
                "total_cpu_cores": total_cpu,
                "total_memory_gb": total_mem,
                "vm_count": cluster_vms.len(),
                "cpu_utilization_pct": (cpu_util * 10.0).round() / 10.0,
                "memory_utilization_pct": (mem_util * 10.0).round() / 10.0
            })
        })
        .collect();
    Value::Array(summaries)
}

pub fn get_cluster_capacity(site: &str, cluster: &str) -> Result<Value, String> {
    let store = cost_store().lock().map_err(|e| e.to_string())?;
    let vms: Vec<&VmUtilization> = store
        .0
        .iter()
        .filter(|v| v.site == site && v.cluster == cluster)
        .collect();

    if vms.is_empty() {
        return Err(format!(
            "Cluster '{}' not found in site '{}'",
            cluster, site
        ));
    }

    let total_cpu: u32 = vms.iter().map(|v| v.cpu_cores).sum();
    let used_cpu = (total_cpu as f64 * vms.iter().map(|v| v.cpu_usage_pct).sum::<f64>()
        / (vms.len() as f64 * 100.0))
        .round() as u32;
    let total_mem: u32 = vms.iter().map(|v| v.memory_gb).sum();
    let used_mem = (total_mem as f64 * vms.iter().map(|v| v.memory_usage_pct).sum::<f64>()
        / (vms.len() as f64 * 100.0))
        .round() as u32;
    let cpu_util = vms.iter().map(|v| v.cpu_usage_pct).sum::<f64>() / vms.len() as f64;
    let mem_util = vms.iter().map(|v| v.memory_usage_pct).sum::<f64>() / vms.len() as f64;

    let vm_list: Vec<Value> = vms
        .iter()
        .map(|v| {
            json!({
                "vm_name": v.vm_name,
                "cpu_cores": v.cpu_cores,
                "memory_gb": v.memory_gb,
                "storage_gb": v.storage_gb,
                "cpu_usage_pct": v.cpu_usage_pct,
                "memory_usage_pct": v.memory_usage_pct,
                "monthly_cost": v.monthly_cost
            })
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "cluster": cluster,
        "total_cpu_cores": total_cpu,
        "used_cpu_cores": used_cpu,
        "total_memory_gb": total_mem,
        "used_memory_gb": used_mem,
        "cpu_utilization_pct": (cpu_util * 10.0).round() / 10.0,
        "memory_utilization_pct": (mem_util * 10.0).round() / 10.0,
        "vm_count": vms.len(),
        "vms": vm_list
    }))
}

pub fn forecast_capacity(site: &str, months: u32) -> Result<Value, String> {
    let capacity = get_site_capacity(site)?;
    let current_cpu = capacity["cpu_utilization_pct"].as_f64().unwrap_or(0.0);
    let current_mem = capacity["memory_utilization_pct"].as_f64().unwrap_or(0.0);
    let total_storage = capacity["total_storage_gb"].as_u64().unwrap_or(0) as u32;
    let used_storage = capacity["used_storage_gb"].as_u64().unwrap_or(0) as u32;
    let current_storage_pct = if total_storage > 0 {
        (used_storage as f64 / total_storage as f64) * 100.0
    } else {
        0.0
    };

    let monthly_growth_cpu = 1.8;
    let monthly_growth_mem = 1.5;
    let monthly_growth_storage = 2.2;

    let projected_cpu = current_cpu + monthly_growth_cpu * months as f64;
    let projected_mem = current_mem + monthly_growth_mem * months as f64;
    let projected_storage = current_storage_pct + monthly_growth_storage * months as f64;

    let at_risk_cpu = projected_cpu > 80.0;
    let at_risk_mem = projected_mem > 80.0;
    let at_risk_storage = projected_storage > 80.0;

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "forecast_months": months,
        "current": {
            "cpu_utilization_pct": current_cpu,
            "memory_utilization_pct": current_mem,
            "storage_utilization_pct": (current_storage_pct * 10.0).round() / 10.0
        },
        "projected": {
            "cpu_utilization_pct": (projected_cpu * 10.0).round() / 10.0,
            "memory_utilization_pct": (projected_mem * 10.0).round() / 10.0,
            "storage_utilization_pct": (projected_storage * 10.0).round() / 10.0
        },
        "risk_flags": {
            "cpu_at_risk": at_risk_cpu,
            "memory_at_risk": at_risk_mem,
            "storage_at_risk": at_risk_storage
        },
        "recommendation": if at_risk_cpu || at_risk_mem || at_risk_storage {
            "Capacity expansion recommended within forecast window"
        } else {
            "Current growth trajectory is sustainable within forecast window"
        }
    }))
}

pub fn get_cost_summary(site: &str) -> Result<Value, String> {
    let store = cost_store().lock().map_err(|e| e.to_string())?;
    let vms: Vec<&VmUtilization> = store.0.iter().filter(|v| v.site == site).collect();

    if vms.is_empty() {
        return Err(format!("Site '{}' not found", site));
    }

    let total_spend: f64 = vms.iter().map(|v| v.monthly_cost).sum();
    let vm_count = vms.len() as u32;
    let avg_cost = total_spend / vm_count as f64;

    let compute_cost: f64 = vms
        .iter()
        .map(|v| v.cpu_cores as f64 * store.1.cost_per_core)
        .sum();
    let storage_cost: f64 = vms
        .iter()
        .map(|v| v.storage_gb as f64 * store.1.cost_per_gb_storage)
        .sum();
    let license_cost: f64 = vms.iter().map(|_| store.1.license_cost_per_vm).sum();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "total_monthly_spend": (total_spend * 100.0).round() / 100.0,
        "vm_count": vm_count,
        "avg_cost_per_vm": (avg_cost * 100.0).round() / 100.0,
        "compute_cost": (compute_cost * 100.0).round() / 100.0,
        "storage_cost": (storage_cost * 100.0).round() / 100.0,
        "license_cost": (license_cost * 100.0).round() / 100.0,
        "pricing_model": {
            "cost_per_core": store.1.cost_per_core,
            "cost_per_gb_ram": store.1.cost_per_gb_ram,
            "cost_per_gb_storage": store.1.cost_per_gb_storage,
            "license_cost_per_vm": store.1.license_cost_per_vm
        }
    }))
}

pub fn get_waste_report(site: &str) -> Result<Value, String> {
    let store = cost_store().lock().map_err(|e| e.to_string())?;
    let vms: Vec<&VmUtilization> = store.0.iter().filter(|v| v.site == site).collect();

    if vms.is_empty() {
        return Err(format!("Site '{}' not found", site));
    }

    let idle: Vec<Value> = vms
        .iter()
        .filter(|v| v.idle)
        .map(|v| {
            json!({
                "vm_name": v.vm_name,
                "cpu_usage_pct": v.cpu_usage_pct,
                "memory_usage_pct": v.memory_usage_pct,
                "monthly_cost": v.monthly_cost,
                "recommendation": "Consider powering off or decommissioning"
            })
        })
        .collect();

    let oversized: Vec<Value> = vms
        .iter()
        .filter(|v| v.oversized)
        .map(|v| {
            json!({
                "vm_name": v.vm_name,
                "cpu_cores": v.cpu_cores,
                "memory_gb": v.memory_gb,
                "cpu_usage_pct": v.cpu_usage_pct,
                "memory_usage_pct": v.memory_usage_pct,
                "monthly_cost": v.monthly_cost,
                "recommendation": format!(
                    "Downsize from {} vCPU / {} GB to {} vCPU / {} GB",
                    v.cpu_cores,
                    v.memory_gb,
                    (v.cpu_cores as f64 * 0.5).ceil() as u32,
                    (v.memory_gb as f64 * 0.5).ceil() as u32,
                )
            })
        })
        .collect();

    let orphaned: Vec<Value> = vms
        .iter()
        .filter(|v| v.orphaned_disk_gb > 0)
        .map(|v| {
            json!({
                "vm_name": v.vm_name,
                "disk_name": format!("{}-orphaned-disk", v.vm_name),
                "size_gb": v.orphaned_disk_gb,
                "monthly_cost": (v.orphaned_disk_gb as f64 * store.1.cost_per_gb_storage * 100.0).round() / 100.0
            })
        })
        .collect();

    let idle_waste: f64 = idle.iter().filter_map(|v| v["monthly_cost"].as_f64()).sum();
    let oversized_waste: f64 = oversized
        .iter()
        .filter_map(|v| v["monthly_cost"].as_f64())
        .map(|c| c * 0.5)
        .sum();
    let orphaned_waste: f64 = orphaned
        .iter()
        .filter_map(|v| v["monthly_cost"].as_f64())
        .sum();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "idle_vms": idle,
        "idle_count": idle.len(),
        "idle_monthly_cost": (idle_waste * 100.0).round() / 100.0,
        "oversized_vms": oversized,
        "oversized_count": oversized.len(),
        "oversized_potential_savings": (oversized_waste * 100.0).round() / 100.0,
        "orphaned_disks": orphaned,
        "orphaned_disk_count": orphaned.len(),
        "orphaned_monthly_cost": (orphaned_waste * 100.0).round() / 100.0,
        "total_waste_monthly": ((idle_waste + oversized_waste + orphaned_waste) * 100.0).round() / 100.0
    }))
}

pub fn get_rightsizing_recommendations(site: &str) -> Result<Value, String> {
    let store = cost_store().lock().map_err(|e| e.to_string())?;
    let vms: Vec<&VmUtilization> = store.0.iter().filter(|v| v.site == site).collect();

    if vms.is_empty() {
        return Err(format!("Site '{}' not found", site));
    }

    let recommendations: Vec<Value> = vms
        .iter()
        .filter(|v| {
            v.idle
                || v.oversized
                || v.cpu_usage_pct > 85.0
                || v.cpu_usage_pct < 15.0 && v.cpu_cores > 2
        })
        .map(|v| {
            let (rec_cpu, rec_mem, reason) = if v.idle {
                (0, 0, "VM is idle — consider decommissioning")
            } else if v.oversized {
                (
                    (v.cpu_cores as f64 * 0.5).ceil() as u32,
                    (v.memory_gb as f64 * 0.5).ceil() as u32,
                    "VM is oversized relative to actual usage",
                )
            } else if v.cpu_usage_pct > 85.0 {
                (
                    (v.cpu_cores as f64 * 1.5).ceil() as u32,
                    v.memory_gb,
                    "CPU constrained — consider upsizing",
                )
            } else {
                (
                    (v.cpu_cores as f64 * 0.5).ceil() as u32,
                    (v.memory_gb as f64 * 0.5).ceil() as u32,
                    "Low utilization — consider downsizing",
                )
            };

            let savings = if rec_cpu == 0 {
                v.monthly_cost
            } else {
                let new_cost = rec_cpu as f64 * store.1.cost_per_core
                    + rec_mem as f64 * store.1.cost_per_gb_ram
                    + v.storage_gb as f64 * store.1.cost_per_gb_storage
                    + store.1.license_cost_per_vm;
                (v.monthly_cost - new_cost).max(0.0)
            };

            json!({
                "vm_name": v.vm_name,
                "current_cpu": v.cpu_cores,
                "recommended_cpu": rec_cpu,
                "current_memory_gb": v.memory_gb,
                "recommended_memory_gb": rec_mem,
                "current_monthly_cost": v.monthly_cost,
                "savings_monthly": (savings * 100.0).round() / 100.0,
                "reason": reason
            })
        })
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "recommendation_count": recommendations.len(),
        "recommendations": recommendations
    }))
}

pub fn get_trend_report(site: &str, metric: &str) -> Result<Value, String> {
    let store = cost_store().lock().map_err(|e| e.to_string())?;
    let vms: Vec<&VmUtilization> = store.0.iter().filter(|v| v.site == site).collect();

    if vms.is_empty() {
        return Err(format!("Site '{}' not found", site));
    }

    let valid_metrics = ["cpu", "memory", "storage"];
    if !valid_metrics.contains(&metric) {
        return Err(format!(
            "Invalid metric '{}'. Valid metrics: cpu, memory, storage",
            metric
        ));
    }

    let now = chrono::Utc::now();
    let data_points: Vec<Value> = (0..12)
        .map(|i| {
            let date = now - chrono::Duration::weeks(i * 4);
            let base_value = match metric {
                "cpu" => vms.iter().map(|v| v.cpu_usage_pct).sum::<f64>() / vms.len() as f64,
                "memory" => vms.iter().map(|v| v.memory_usage_pct).sum::<f64>() / vms.len() as f64,
                _ => {
                    let used = vms.iter().map(|v| v.storage_gb as f64).sum::<f64>();
                    let total = used;
                    (used / total * 100.0).max(0.0)
                }
            };
            let jitter = (i as f64 - 6.0) * 0.5;
            let value = (base_value + jitter).clamp(0.0, 100.0);

            json!({
                "date": date.format("%Y-%m-%d").to_string(),
                "value": (value * 10.0).round() / 10.0
            })
        })
        .rev()
        .collect();

    Ok(json!({
        "source": "dry-run",
        "site": site,
        "metric": metric,
        "period": "12 months",
        "data_points": data_points
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_site_capacity_defra() {
        let result = get_site_capacity("DEFRA").unwrap();
        assert_eq!(result["source"], "dry-run");
        assert_eq!(result["site"], "DEFRA");
        assert!(result["total_cpu_cores"].as_u64().unwrap() > 0);
        assert!(result["total_memory_gb"].as_u64().unwrap() > 0);
        assert!(result["vm_count"].as_u64().unwrap() > 0);
        assert!(result["cpu_utilization_pct"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn test_get_site_capacity_gblon() {
        let result = get_site_capacity("GBLON").unwrap();
        assert_eq!(result["site"], "GBLON");
        assert!(!result["clusters"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_get_cluster_capacity() {
        let result = get_cluster_capacity("DEFRA", "defra-general-cluster").unwrap();
        assert_eq!(result["site"], "DEFRA");
        assert_eq!(result["cluster"], "defra-general-cluster");
        assert!(result["vm_count"].as_u64().unwrap() > 0);
        assert!(result["vms"].as_array().is_some());
    }

    #[test]
    fn test_forecast_capacity() {
        let result = forecast_capacity("DEFRA", 6).unwrap();
        assert_eq!(result["forecast_months"], 6);
        let projected_cpu = result["projected"]["cpu_utilization_pct"].as_f64().unwrap();
        let current_cpu = result["current"]["cpu_utilization_pct"].as_f64().unwrap();
        assert!(projected_cpu > current_cpu);
        // cpu_at_risk field must be present and parseable as bool (may be true or false)
        assert!(result["risk_flags"]["cpu_at_risk"].as_bool().is_some());
    }

    #[test]
    fn test_get_cost_summary() {
        let result = get_cost_summary("GBLON").unwrap();
        assert!(result["total_monthly_spend"].as_f64().unwrap() > 0.0);
        assert!(result["vm_count"].as_u64().unwrap() > 0);
        assert!(result["avg_cost_per_vm"].as_f64().unwrap() > 0.0);
        assert_eq!(result["pricing_model"]["cost_per_core"], 12.5);
    }

    #[test]
    fn test_get_waste_report() {
        let result = get_waste_report("DEFRA").unwrap();
        assert!(result["idle_count"].as_u64().unwrap() > 0);
        assert!(result["idle_monthly_cost"].as_f64().unwrap() > 0.0);
        assert!(result["total_waste_monthly"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn test_get_rightsizing_recommendations() {
        let result = get_rightsizing_recommendations("GBLON").unwrap();
        assert!(result["recommendation_count"].as_u64().unwrap() > 0);
        let recs = result["recommendations"].as_array().unwrap();
        assert!(!recs.is_empty());
        assert!(recs[0]["reason"].as_str().is_some());
    }

    #[test]
    fn test_get_trend_report() {
        let result = get_trend_report("DEFRA", "cpu").unwrap();
        assert_eq!(result["metric"], "cpu");
        assert_eq!(result["site"], "DEFRA");
        let points = result["data_points"].as_array().unwrap();
        assert_eq!(points.len(), 12);
        assert!(points[0]["date"].as_str().is_some());
        assert!(points[0]["value"].as_f64().is_some());
    }

    #[test]
    fn test_get_trend_report_invalid_metric() {
        assert!(get_trend_report("DEFRA", "network").is_err());
    }

    #[test]
    fn test_site_not_found() {
        assert!(get_site_capacity("NONEXISTENT").is_err());
        assert!(get_cost_summary("NONEXISTENT").is_err());
        assert!(get_waste_report("NONEXISTENT").is_err());
    }

    #[test]
    fn test_trend_report_memory() {
        let result = get_trend_report("GBLON", "memory").unwrap();
        assert_eq!(result["metric"], "memory");
    }

    #[test]
    fn test_trend_report_storage() {
        let result = get_trend_report("DEFRA", "storage").unwrap();
        assert_eq!(result["metric"], "storage");
    }
}
