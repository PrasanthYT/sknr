use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Service {
    pub name: String,
    pub path: String,
    pub internet_facing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub relationship: DependencyRelationship,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyRelationship {
    Direct,
    Transitive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScannedService {
    pub name: String,
    pub path: String,
    pub internet_facing: bool,
    pub package_name: String,
    pub manifest_path: String,
    pub lockfile_path: String,
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    pub root: String,
    pub topology: ServiceTopology,
    pub inventory: Vec<InventoryPackage>,
    pub services: Vec<ScannedService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InventoryPackage {
    pub name: String,
    pub version: String,
    pub relationships: Vec<DependencyRelationship>,
    pub used_by: Vec<PackageUsage>,
    pub advisories: Vec<AdvisorySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageUsage {
    pub service: String,
    pub relationship: DependencyRelationship,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdvisorySummary {
    pub id: String,
    pub modified: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceTopology {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub node_type: TopologyNodeType,
    pub path: Option<String>,
    pub internet_facing: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyNodeType {
    External,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TopologyEdge {
    pub from: String,
    pub to: String,
    pub relationship: TopologyEdgeRelationship,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyEdgeRelationship {
    InternetExposure,
}
