use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactNode {
    pub ci_name: String,
    pub ci_type: CiType,
    pub relationships: Vec<String>,
    pub criticality: Criticality,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CiType {
    Server,
    Application,
    Database,
    Network,
    Storage,
}

impl std::fmt::Display for CiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CiType::Server => write!(f, "Server"),
            CiType::Application => write!(f, "Application"),
            CiType::Database => write!(f, "Database"),
            CiType::Network => write!(f, "Network"),
            CiType::Storage => write!(f, "Storage"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Criticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Criticality::Low => write!(f, "Low"),
            Criticality::Medium => write!(f, "Medium"),
            Criticality::High => write!(f, "High"),
            Criticality::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactAnalysis {
    pub change_description: String,
    pub affected_cis: Vec<ImpactedCi>,
    pub risk_level: RiskLevel,
    pub estimated_downtime: String,
    pub rollback_complexity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImpactedCi {
    pub ci_name: String,
    pub ci_type: CiType,
    pub criticality: Criticality,
    pub impact_reason: String,
    pub is_direct: bool,
}

fn seed_graph() -> HashMap<String, ImpactNode> {
    let mut graph = HashMap::new();

    graph.insert(
        "app-portal".into(),
        ImpactNode {
            ci_name: "app-portal".into(),
            ci_type: CiType::Application,
            relationships: vec!["env-prod-defra".into(), "db-portal".into()],
            criticality: Criticality::Critical,
        },
    );

    graph.insert(
        "app-billing".into(),
        ImpactNode {
            ci_name: "app-billing".into(),
            ci_type: CiType::Application,
            relationships: vec!["env-prod-defra".into(), "db-billing".into()],
            criticality: Criticality::High,
        },
    );

    graph.insert(
        "env-prod-defra".into(),
        ImpactNode {
            ci_name: "env-prod-defra".into(),
            ci_type: CiType::Server,
            relationships: vec![
                "vm-defra-web01".into(),
                "vm-defra-web02".into(),
                "san-defra-tier1".into(),
            ],
            criticality: Criticality::Critical,
        },
    );

    graph.insert(
        "db-portal".into(),
        ImpactNode {
            ci_name: "db-portal".into(),
            ci_type: CiType::Database,
            relationships: vec!["vm-defra-db01".into(), "san-defra-tier1".into()],
            criticality: Criticality::Critical,
        },
    );

    graph.insert(
        "db-billing".into(),
        ImpactNode {
            ci_name: "db-billing".into(),
            ci_type: CiType::Database,
            relationships: vec!["vm-defra-db02".into(), "san-defra-tier2".into()],
            criticality: Criticality::High,
        },
    );

    graph.insert(
        "vm-defra-web01".into(),
        ImpactNode {
            ci_name: "vm-defra-web01".into(),
            ci_type: CiType::Server,
            relationships: vec!["san-defra-tier1".into(), "net-defra-vlan100".into()],
            criticality: Criticality::High,
        },
    );

    graph.insert(
        "vm-defra-web02".into(),
        ImpactNode {
            ci_name: "vm-defra-web02".into(),
            ci_type: CiType::Server,
            relationships: vec!["san-defra-tier1".into(), "net-defra-vlan100".into()],
            criticality: Criticality::High,
        },
    );

    graph.insert(
        "vm-defra-db01".into(),
        ImpactNode {
            ci_name: "vm-defra-db01".into(),
            ci_type: CiType::Server,
            relationships: vec!["san-defra-tier1".into(), "net-defra-vlan200".into()],
            criticality: Criticality::Critical,
        },
    );

    graph.insert(
        "vm-defra-db02".into(),
        ImpactNode {
            ci_name: "vm-defra-db02".into(),
            ci_type: CiType::Server,
            relationships: vec!["san-defra-tier2".into(), "net-defra-vlan200".into()],
            criticality: Criticality::High,
        },
    );

    graph.insert(
        "san-defra-tier1".into(),
        ImpactNode {
            ci_name: "san-defra-tier1".into(),
            ci_type: CiType::Storage,
            relationships: vec![],
            criticality: Criticality::Critical,
        },
    );

    graph.insert(
        "san-defra-tier2".into(),
        ImpactNode {
            ci_name: "san-defra-tier2".into(),
            ci_type: CiType::Storage,
            relationships: vec![],
            criticality: Criticality::High,
        },
    );

    graph.insert(
        "net-defra-vlan100".into(),
        ImpactNode {
            ci_name: "net-defra-vlan100".into(),
            ci_type: CiType::Network,
            relationships: vec![],
            criticality: Criticality::High,
        },
    );

    graph.insert(
        "net-defra-vlan200".into(),
        ImpactNode {
            ci_name: "net-defra-vlan200".into(),
            ci_type: CiType::Network,
            relationships: vec![],
            criticality: Criticality::High,
        },
    );

    graph
}

fn ci_graph() -> &'static HashMap<String, ImpactNode> {
    static GRAPH: OnceLock<HashMap<String, ImpactNode>> = OnceLock::new();
    GRAPH.get_or_init(seed_graph)
}

pub fn get_ci_graph() -> Vec<ImpactNode> {
    ci_graph().values().cloned().collect()
}

pub fn get_upstream_dependencies(ci_name: &str) -> Vec<ImpactNode> {
    let graph = ci_graph();
    graph
        .values()
        .filter(|node| node.relationships.contains(&ci_name.to_string()))
        .cloned()
        .collect()
}

pub fn get_downstream_dependencies(ci_name: &str) -> Vec<ImpactNode> {
    let graph = ci_graph();
    let Some(node) = graph.get(ci_name) else {
        return Vec::new();
    };
    node.relationships
        .iter()
        .filter_map(|rel| graph.get(rel).cloned())
        .collect()
}

fn collect_transitive_downstream(
    graph: &HashMap<String, ImpactNode>,
    ci_name: &str,
    visited: &mut HashSet<String>,
    result: &mut Vec<ImpactedCi>,
) {
    if !visited.insert(ci_name.to_string()) {
        return;
    }
    let Some(node) = graph.get(ci_name) else {
        return;
    };
    for rel in &node.relationships {
        collect_transitive_downstream(graph, rel, visited, result);
        if let Some(child) = graph.get(rel) {
            result.push(ImpactedCi {
                ci_name: child.ci_name.clone(),
                ci_type: child.ci_type.clone(),
                criticality: child.criticality.clone(),
                impact_reason: format!("Downstream dependency of {}", ci_name),
                is_direct: node.relationships.contains(rel),
            });
        }
    }
}

pub fn analyze_impact(
    change_description: &str,
    target_cis: &[String],
) -> Result<ImpactAnalysis, String> {
    if target_cis.is_empty() {
        return Err("At least one target CI is required for impact analysis".into());
    }

    let graph = ci_graph();

    for ci in target_cis {
        if !graph.contains_key(ci) {
            return Err(format!("Unknown CI: {}", ci));
        }
    }

    let mut affected_map: HashMap<String, ImpactedCi> = HashMap::new();
    let mut visited = HashSet::new();

    for target in target_cis {
        if let Some(node) = graph.get(target) {
            affected_map
                .entry(target.clone())
                .or_insert_with(|| ImpactedCi {
                    ci_name: node.ci_name.clone(),
                    ci_type: node.ci_type.clone(),
                    criticality: node.criticality.clone(),
                    impact_reason: format!("Direct target of change: {}", change_description),
                    is_direct: true,
                });
        }
        collect_transitive_downstream(graph, target, &mut visited, &mut Vec::new());
        for downstream in target_cis
            .iter()
            .flat_map(|t| get_downstream_dependencies(t))
        {
            affected_map
                .entry(downstream.ci_name.clone())
                .or_insert(ImpactedCi {
                    ci_name: downstream.ci_name.clone(),
                    ci_type: downstream.ci_type.clone(),
                    criticality: downstream.criticality.clone(),
                    impact_reason: format!("Downstream of {}", target),
                    is_direct: false,
                });
        }
    }

    let affected_cis: Vec<ImpactedCi> = affected_map.into_values().collect();

    let max_criticality = target_cis
        .iter()
        .filter_map(|ci| graph.get(ci))
        .map(|n| n.criticality.clone())
        .max()
        .unwrap_or(Criticality::Low);

    let risk_level = match max_criticality {
        Criticality::Critical => RiskLevel::Critical,
        Criticality::High => RiskLevel::High,
        Criticality::Medium => RiskLevel::Medium,
        Criticality::Low => RiskLevel::Low,
    };

    let estimated_downtime = match risk_level {
        RiskLevel::Critical => "4-8 hours",
        RiskLevel::High => "2-4 hours",
        RiskLevel::Medium => "30 minutes - 2 hours",
        RiskLevel::Low => "0-30 minutes",
    };

    let rollback_complexity = if affected_cis.len() > 5 {
        "High — many downstream CIs affected, coordinated rollback required"
    } else if affected_cis.len() > 2 {
        "Medium — several downstream CIs, rollback needs sequencing"
    } else {
        "Low — limited blast radius, straightforward rollback"
    };

    Ok(ImpactAnalysis {
        change_description: change_description.to_string(),
        affected_cis,
        risk_level,
        estimated_downtime: estimated_downtime.to_string(),
        rollback_complexity: rollback_complexity.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ci_graph_has_expected_nodes() {
        let graph = get_ci_graph();
        assert!(graph.len() >= 10);
        let names: HashSet<&str> = graph.iter().map(|n| n.ci_name.as_str()).collect();
        assert!(names.contains("app-portal"));
        assert!(names.contains("san-defra-tier1"));
    }

    #[test]
    fn test_downstream_dependencies() {
        let deps = get_downstream_dependencies("app-portal");
        assert!(!deps.is_empty());
        let dep_names: Vec<&str> = deps.iter().map(|d| d.ci_name.as_str()).collect();
        assert!(dep_names.contains(&"env-prod-defra"));
        assert!(dep_names.contains(&"db-portal"));
    }

    #[test]
    fn test_upstream_dependencies() {
        let deps = get_upstream_dependencies("san-defra-tier1");
        assert!(!deps.is_empty());
        let dep_names: Vec<&str> = deps.iter().map(|d| d.ci_name.as_str()).collect();
        assert!(dep_names.contains(&"env-prod-defra"));
        assert!(dep_names.contains(&"vm-defra-web01"));
    }

    #[test]
    fn test_analyze_impact_single_ci() {
        let result =
            analyze_impact("Patch san-defra-tier1 firmware", &["san-defra-tier1".into()]).unwrap();
        assert_eq!(result.risk_level, RiskLevel::Critical);
        assert!(!result.affected_cis.is_empty());
        assert!(
            result
                .affected_cis
                .iter()
                .any(|ci| ci.ci_name == "san-defra-tier1" && ci.is_direct)
        );
    }

    #[test]
    fn test_analyze_impact_unknown_ci_fails() {
        let result = analyze_impact("Patch unknown CI", &["no-such-ci".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_impact_empty_targets_fails() {
        let result = analyze_impact("Empty change", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_impact_multiple_targets() {
        let result = analyze_impact(
            "Network maintenance for VLAN100 and VLAN200",
            &["net-defra-vlan100".into(), "net-defra-vlan200".into()],
        )
        .unwrap();
        assert!(result.affected_cis.len() >= 2);
        assert_eq!(result.risk_level, RiskLevel::High);
    }

    #[test]
    fn test_upstream_dependencies_none_for_leaf() {
        let deps = get_upstream_dependencies("app-portal");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_downstream_dependencies_leaf_ci() {
        let deps = get_downstream_dependencies("san-defra-tier1");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_ci_type_display() {
        assert_eq!(CiType::Server.to_string(), "Server");
        assert_eq!(CiType::Database.to_string(), "Database");
        assert_eq!(CiType::Application.to_string(), "Application");
    }

    #[test]
    fn test_criticality_ordering() {
        assert!(Criticality::Critical > Criticality::High);
        assert!(Criticality::High > Criticality::Medium);
        assert!(Criticality::Medium > Criticality::Low);
    }
}
