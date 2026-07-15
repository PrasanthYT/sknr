use crate::model::{
    ScannedService, ServiceTopology, TopologyEdge, TopologyEdgeRelationship, TopologyNode,
    TopologyNodeType,
};
use petgraph::graph::DiGraph;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use thiserror::Error;

const INTERNET_NODE_ID: &str = "internet";

#[derive(Debug, Error)]
pub enum TopologyError {
    #[error("missing topology config: {0}")]
    MissingConfig(String),
    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse YAML in {path}: {source}")]
    ParseYaml {
        path: String,
        source: serde_yaml::Error,
    },
    #[error("topology config declares duplicate service path: {0}")]
    DuplicateServicePath(String),
    #[error("topology config references unknown service path: {0}")]
    UnknownServicePath(String),
    #[error("discovered service is missing from topology config: {0}")]
    MissingServicePath(String),
}

#[derive(Debug, Deserialize)]
struct SknrConfig {
    services: Vec<ConfiguredService>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConfiguredService {
    name: String,
    path: String,
    internet_facing: bool,
}

pub fn apply_topology_config(
    root: &Path,
    services: &mut [ScannedService],
) -> Result<ServiceTopology, TopologyError> {
    let config_path = root.join("sknr.config.yaml");
    if !config_path.exists() {
        return Err(TopologyError::MissingConfig(
            config_path.display().to_string(),
        ));
    }

    let config = read_config(&config_path)?;
    let by_path = index_configured_services(config.services)?;
    validate_config_paths(&by_path, services)?;

    for service in services.iter_mut() {
        let configured = by_path
            .get(&service.path)
            .ok_or_else(|| TopologyError::MissingServicePath(service.path.clone()))?;
        service.name = configured.name.clone();
        service.internet_facing = configured.internet_facing;
    }

    Ok(build_topology(services))
}

fn read_config(path: &Path) -> Result<SknrConfig, TopologyError> {
    let raw = fs::read_to_string(path).map_err(|source| TopologyError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    serde_yaml::from_str(&raw).map_err(|source| TopologyError::ParseYaml {
        path: path.display().to_string(),
        source,
    })
}

fn index_configured_services(
    services: Vec<ConfiguredService>,
) -> Result<BTreeMap<String, ConfiguredService>, TopologyError> {
    let mut by_path = BTreeMap::new();
    for service in services {
        let path = service.path.clone();
        if by_path.insert(path.clone(), service).is_some() {
            return Err(TopologyError::DuplicateServicePath(path));
        }
    }
    Ok(by_path)
}

fn validate_config_paths(
    configured: &BTreeMap<String, ConfiguredService>,
    services: &[ScannedService],
) -> Result<(), TopologyError> {
    let discovered_paths = services
        .iter()
        .map(|service| service.path.clone())
        .collect::<BTreeSet<_>>();

    for path in configured.keys() {
        if !discovered_paths.contains(path) {
            return Err(TopologyError::UnknownServicePath(path.clone()));
        }
    }

    for path in discovered_paths {
        if !configured.contains_key(&path) {
            return Err(TopologyError::MissingServicePath(path));
        }
    }

    Ok(())
}

fn build_topology(services: &[ScannedService]) -> ServiceTopology {
    let mut graph = DiGraph::<String, TopologyEdgeRelationship>::new();
    let internet = graph.add_node(INTERNET_NODE_ID.to_string());
    let mut nodes = vec![TopologyNode {
        id: INTERNET_NODE_ID.to_string(),
        label: "Internet".to_string(),
        node_type: TopologyNodeType::External,
        path: None,
        internet_facing: None,
    }];
    let mut edges = Vec::new();

    for service in services {
        let service_id = format!("service:{}", service.name);
        let service_node = graph.add_node(service_id.clone());
        nodes.push(TopologyNode {
            id: service_id.clone(),
            label: service.name.clone(),
            node_type: TopologyNodeType::Service,
            path: Some(service.path.clone()),
            internet_facing: Some(service.internet_facing),
        });

        if service.internet_facing {
            graph.add_edge(
                internet,
                service_node,
                TopologyEdgeRelationship::InternetExposure,
            );
            edges.push(TopologyEdge {
                from: INTERNET_NODE_ID.to_string(),
                to: service_id,
                relationship: TopologyEdgeRelationship::InternetExposure,
            });
        }
    }

    ServiceTopology { nodes, edges }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Dependency;

    fn service(name: &str, path: &str) -> ScannedService {
        ScannedService {
            name: name.to_string(),
            path: path.to_string(),
            internet_facing: false,
            package_name: format!("@sknr-demo/{name}"),
            manifest_path: format!("{path}/package.json"),
            lockfile_path: "package-lock.json".to_string(),
            dependencies: Vec::<Dependency>::new(),
        }
    }

    #[test]
    fn builds_internet_edges_for_facing_services() {
        let mut services = vec![
            service("api-gateway", "apps/api-gateway"),
            service("user-service", "apps/user-service"),
        ];
        services[0].internet_facing = true;

        let topology = build_topology(&services);

        assert_eq!(topology.nodes.len(), 3);
        assert_eq!(topology.edges.len(), 1);
        assert_eq!(topology.edges[0].from, "internet");
        assert_eq!(topology.edges[0].to, "service:api-gateway");
    }

    #[test]
    fn rejects_unknown_config_paths() {
        let configured = BTreeMap::from([(
            "apps/missing".to_string(),
            ConfiguredService {
                name: "missing".to_string(),
                path: "apps/missing".to_string(),
                internet_facing: true,
            },
        )]);
        let services = vec![service("api-gateway", "apps/api-gateway")];

        let error = validate_config_paths(&configured, &services).unwrap_err();

        assert!(matches!(error, TopologyError::UnknownServicePath(path) if path == "apps/missing"));
    }
}
