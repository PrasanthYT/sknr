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
    pub package_name: String,
    pub manifest_path: String,
    pub lockfile_path: String,
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    pub root: String,
    pub services: Vec<ScannedService>,
}
