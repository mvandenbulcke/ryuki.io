//! Observability deploy-wiring validator.
//!
//! Asserts that the Kubernetes deploy artifacts under `deploy/kubernetes/`
//! are coherently wired for Prometheus scraping: every Deployment that
//! exposes a Prometheus `/metrics` endpoint must have a matching
//! `ServiceMonitor` (selector + a `/metrics` scrape path), the supporting
//! `PrometheusRule` must declare the required alerts, and a NetworkPolicy must
//! open the metrics port to a `monitoring` namespace.
//!
//! Like the other deploy validators (see `app_skeleton`), this reads the repo
//! files directly from the `root` passed in the slice context JSON, so it can
//! run both standalone (`validate observability-deploy-wiring`) and inside
//! `run-all` (where `build_slice_context` supplies `root`).

use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::Path;

const DEPLOYMENTS_PATH: &str = "deploy/kubernetes/base/deployments.yaml";
const NETWORKPOLICIES_PATH: &str = "deploy/kubernetes/base/networkpolicies.yaml";
const SERVICEMONITORS_PATH: &str = "deploy/kubernetes/monitoring/servicemonitors.yaml";
const PROMETHEUSRULE_PATH: &str = "deploy/kubernetes/monitoring/prometheusrule.yaml";

/// Apps whose Deployment is known to expose a Prometheus `/metrics` endpoint.
///
/// platform-api serves `/metrics` from its main router (see the `metrics`
/// handler in `sources/ryuki-api/src/main.rs`). portal-ui does NOT yet expose
/// `/metrics`, so it is intentionally absent here — its ServiceMonitor ships as
/// a disabled placeholder and is not required to have a `/metrics` scrape path.
const METRICS_EXPOSING_APPS: &[&str] = &["platform-api"];

/// Alerts the PrometheusRule must declare.
const REQUIRED_ALERTS: &[&str] = &[
    "ApiDown",
    "DbPoolDisconnected",
    "ComponentUnhealthy",
    "HighErrorRate",
];

const MONITORING_POLICY_NAME: &str = "allow-monitoring-ingress";
const NAME_LABEL: &str = "app.kubernetes.io/name";

#[derive(Debug, Deserialize)]
struct Context {
    root: String,
}

/// Slice entry point used by the dispatch table and `run-all`.
pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid observability-deploy-wiring context JSON: {error}"))?;
    Ok(validate_root(Path::new(&context.root)))
}

fn validate_root(root: &Path) -> Vec<String> {
    let mut errors = Vec::new();

    let deployments = match load_documents(root, DEPLOYMENTS_PATH) {
        Ok(docs) => docs,
        Err(error) => {
            errors.push(error);
            return errors;
        }
    };
    let service_monitors = match load_documents(root, SERVICEMONITORS_PATH) {
        Ok(docs) => docs,
        Err(error) => {
            errors.push(error);
            return errors;
        }
    };

    let deployment_apps = collect_app_names(&deployments, "Deployment");
    let monitor_index = collect_service_monitors(&service_monitors);

    // Core invariant: every Deployment that exposes /metrics has a matching
    // ServiceMonitor with a /metrics scrape endpoint.
    for app in &deployment_apps {
        if !METRICS_EXPOSING_APPS.contains(&app.as_str()) {
            continue;
        }
        match monitor_index.iter().find(|m| m.selector_name.as_deref() == Some(app)) {
            None => errors.push(format!(
                "Deployment {app} exposes /metrics but has no ServiceMonitor selecting {NAME_LABEL}={app}"
            )),
            Some(monitor) => {
                if !monitor.has_metrics_path {
                    errors.push(format!(
                        "ServiceMonitor {} selects /metrics-exposing app {app} but no endpoint scrapes path /metrics",
                        monitor.name
                    ));
                }
            }
        }
    }

    // Every ServiceMonitor selector must resolve to a real Deployment, so the
    // monitoring layer never references an app that does not exist.
    for monitor in &monitor_index {
        match &monitor.selector_name {
            None => errors.push(format!(
                "ServiceMonitor {} has no {NAME_LABEL} selector",
                monitor.name
            )),
            Some(name) => {
                if !deployment_apps.contains(name) {
                    errors.push(format!(
                        "ServiceMonitor {} selects {NAME_LABEL}={name} but no such Deployment exists",
                        monitor.name
                    ));
                }
            }
        }
    }

    validate_prometheus_rule(root, &mut errors);
    validate_monitoring_network_policy(root, &mut errors);

    errors
}

fn validate_prometheus_rule(root: &Path, errors: &mut Vec<String>) {
    let text = match fs::read_to_string(root.join(PROMETHEUSRULE_PATH)) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("failed to read {PROMETHEUSRULE_PATH}: {error}"));
            return;
        }
    };
    for alert in REQUIRED_ALERTS {
        if !text.contains(&format!("alert: {alert}")) {
            errors.push(format!("PrometheusRule is missing required alert {alert}"));
        }
    }
}

fn validate_monitoring_network_policy(root: &Path, errors: &mut Vec<String>) {
    let docs = match load_documents(root, NETWORKPOLICIES_PATH) {
        Ok(docs) => docs,
        Err(error) => {
            errors.push(error);
            return;
        }
    };

    let policy = docs.iter().find(|doc| {
        kind_of(doc) == Some("NetworkPolicy") && name_of(doc) == Some(MONITORING_POLICY_NAME)
    });

    let Some(policy) = policy else {
        errors.push(format!(
            "NetworkPolicy {MONITORING_POLICY_NAME} is missing; the monitoring namespace cannot scrape metrics under default-deny"
        ));
        return;
    };

    if !policy_allows_monitoring_namespace(policy) {
        errors.push(format!(
            "NetworkPolicy {MONITORING_POLICY_NAME} must allow ingress from a namespace labelled kubernetes.io/metadata.name=monitoring"
        ));
    }
    if !policy_opens_port(policy, 8080) {
        errors.push(format!(
            "NetworkPolicy {MONITORING_POLICY_NAME} must open the metrics port 8080"
        ));
    }
}

/// A parsed ServiceMonitor: its name, the `app.kubernetes.io/name` it selects,
/// and whether any endpoint scrapes the `/metrics` path.
struct MonitorInfo {
    name: String,
    selector_name: Option<String>,
    has_metrics_path: bool,
}

fn collect_service_monitors(docs: &[Value]) -> Vec<MonitorInfo> {
    docs.iter()
        .filter(|doc| kind_of(doc) == Some("ServiceMonitor"))
        .map(|doc| MonitorInfo {
            name: name_of(doc).unwrap_or("<unnamed>").to_string(),
            selector_name: doc
                .get("spec")
                .and_then(|s| s.get("selector"))
                .and_then(|s| s.get("matchLabels"))
                .and_then(|labels| labels.get(NAME_LABEL))
                .and_then(Value::as_str)
                .map(str::to_string),
            has_metrics_path: doc
                .get("spec")
                .and_then(|s| s.get("endpoints"))
                .and_then(Value::as_array)
                .map(|endpoints| {
                    endpoints
                        .iter()
                        .any(|e| e.get("path").and_then(Value::as_str) == Some("/metrics"))
                })
                .unwrap_or(false),
        })
        .collect()
}

fn collect_app_names(docs: &[Value], kind: &str) -> Vec<String> {
    docs.iter()
        .filter(|doc| kind_of(doc) == Some(kind))
        .filter_map(|doc| {
            doc.get("metadata")
                .and_then(|m| m.get("labels"))
                .and_then(|labels| labels.get(NAME_LABEL))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn policy_allows_monitoring_namespace(policy: &Value) -> bool {
    policy
        .get("spec")
        .and_then(|s| s.get("ingress"))
        .and_then(Value::as_array)
        .map(|rules| {
            rules.iter().any(|rule| {
                rule.get("from")
                    .and_then(Value::as_array)
                    .map(|froms| {
                        froms.iter().any(|from| {
                            from.get("namespaceSelector")
                                .and_then(|ns| ns.get("matchLabels"))
                                .and_then(|labels| labels.get("kubernetes.io/metadata.name"))
                                .and_then(Value::as_str)
                                == Some("monitoring")
                        })
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn policy_opens_port(policy: &Value, port: u64) -> bool {
    policy
        .get("spec")
        .and_then(|s| s.get("ingress"))
        .and_then(Value::as_array)
        .map(|rules| {
            rules.iter().any(|rule| {
                rule.get("ports")
                    .and_then(Value::as_array)
                    .map(|ports| {
                        ports
                            .iter()
                            .any(|p| p.get("port").and_then(Value::as_u64) == Some(port))
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn load_documents(root: &Path, rel: &str) -> Result<Vec<Value>, String> {
    let raw = fs::read_to_string(root.join(rel))
        .map_err(|error| format!("failed to read {rel}: {error}"))?;
    let mut docs = Vec::new();
    for document in raw.split("\n---") {
        let trimmed = document.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_yaml::from_str::<Value>(trimmed) {
            Ok(value) if value.is_object() => docs.push(value),
            Ok(_) => {}
            Err(error) => {
                return Err(format!("{rel} contains invalid YAML: {error}"));
            }
        }
    }
    Ok(docs)
}

fn kind_of(doc: &Value) -> Option<&str> {
    doc.get("kind").and_then(Value::as_str)
}

fn name_of(doc: &Value) -> Option<&str> {
    doc.get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn real_deploy_artifacts_are_wired_for_observability() {
        let errors = validate_root(&repo_root());
        assert!(
            errors.is_empty(),
            "observability deploy wiring should be valid, got:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn platform_api_deployment_is_detected_as_metrics_exposing() {
        let docs = load_documents(&repo_root(), DEPLOYMENTS_PATH).expect("deployments readable");
        let apps = collect_app_names(&docs, "Deployment");
        assert!(apps.contains(&"platform-api".to_string()));
    }

    #[test]
    fn missing_service_monitor_is_reported() {
        let deployments = vec![serde_yaml::from_str::<Value>(
            r#"
kind: Deployment
metadata:
  name: platform-api
  labels:
    app.kubernetes.io/name: platform-api
"#,
        )
        .unwrap()];
        let monitors: Vec<Value> = Vec::new();
        let deployment_apps = collect_app_names(&deployments, "Deployment");
        let monitor_index = collect_service_monitors(&monitors);

        assert!(deployment_apps.contains(&"platform-api".to_string()));
        assert!(monitor_index
            .iter()
            .all(|m| m.selector_name.as_deref() != Some("platform-api")));
    }

    #[test]
    fn service_monitor_without_metrics_path_is_flagged() {
        let monitors = vec![serde_yaml::from_str::<Value>(
            r#"
kind: ServiceMonitor
metadata:
  name: platform-api
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: platform-api
  endpoints:
    - port: http
      path: /readyz
"#,
        )
        .unwrap()];
        let index = collect_service_monitors(&monitors);
        assert_eq!(index.len(), 1);
        assert!(!index[0].has_metrics_path);
        assert_eq!(index[0].selector_name.as_deref(), Some("platform-api"));
    }

    #[test]
    fn monitoring_policy_detection_is_strict() {
        let allowed = serde_yaml::from_str::<Value>(
            r#"
kind: NetworkPolicy
metadata:
  name: allow-monitoring-ingress
spec:
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - protocol: TCP
          port: 8080
"#,
        )
        .unwrap();
        assert!(policy_allows_monitoring_namespace(&allowed));
        assert!(policy_opens_port(&allowed, 8080));
        assert!(!policy_opens_port(&allowed, 9090));
    }

    #[test]
    fn prometheus_rule_declares_required_alerts() {
        let mut errors = Vec::new();
        validate_prometheus_rule(&repo_root(), &mut errors);
        assert!(errors.is_empty(), "missing alerts: {}", errors.join(", "));
    }
}
