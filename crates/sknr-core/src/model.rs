use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub path: String,
    pub internet_facing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub relationship: DependencyRelationship,
    pub reachability: ReachabilitySignal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyRelationship {
    Direct,
    Transitive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannedService {
    pub name: String,
    pub path: String,
    pub internet_facing: bool,
    pub package_name: String,
    pub manifest_path: String,
    pub lockfile_path: String,
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub root: String,
    pub topology: ServiceTopology,
    pub inventory: Vec<InventoryPackage>,
    pub services: Vec<ScannedService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryPackage {
    pub name: String,
    pub version: String,
    pub relationships: Vec<DependencyRelationship>,
    pub used_by: Vec<PackageUsage>,
    pub advisories: Vec<AdvisorySummary>,
    pub priority: Option<PriorityAssessment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageUsage {
    pub service: String,
    pub relationship: DependencyRelationship,
    pub internet_facing: bool,
    pub reachability: ReachabilitySignal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilitySignal {
    pub imported: bool,
    pub evidence: Vec<ReachabilityEvidence>,
}

impl ReachabilitySignal {
    pub fn not_found() -> Self {
        Self {
            imported: false,
            evidence: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityEvidence {
    pub path: String,
    pub line: usize,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisorySummary {
    pub id: String,
    pub modified: Option<String>,
    pub aliases: Vec<String>,
    pub cve_aliases: Vec<String>,
    pub kev_match: Option<KevMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KevMatch {
    pub cve_id: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub due_date: String,
    pub known_ransomware_campaign_use: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorityAssessment {
    pub bucket: PriorityBucket,
    pub reasons: Vec<String>,
    pub model: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityBucket {
    FixNow,
    ThisSprint,
    Monitor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceTopology {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub node_type: TopologyNodeType,
    pub path: Option<String>,
    pub internet_facing: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyNodeType {
    External,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub from: String,
    pub to: String,
    pub relationship: TopologyEdgeRelationship,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyEdgeRelationship {
    InternetExposure,
}
