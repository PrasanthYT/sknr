#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub path: String,
    pub internet_facing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub package: String,
    pub version: String,
    pub direct: bool,
}

