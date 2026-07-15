use crate::model::{Dependency, DependencyRelationship, ScanReport, ScannedService};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("scan root does not exist: {0}")]
    RootNotFound(String),
    #[error("missing root package.json: {0}")]
    MissingRootManifest(String),
    #[error("missing root package-lock.json: {0}")]
    MissingLockfile(String),
    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse JSON in {path}: {source}")]
    ParseJson {
        path: String,
        source: serde_json::Error,
    },
    #[error("root package.json does not declare npm workspaces")]
    MissingWorkspaces,
    #[error("workspace pattern is unsupported: {0}")]
    UnsupportedWorkspacePattern(String),
    #[error("workspace package is missing a name: {0}")]
    MissingPackageName(String),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Workspaces {
    Array(Vec<String>),
    Object { packages: Vec<String> },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageManifest {
    name: Option<String>,
    workspaces: Option<Workspaces>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default)]
    dev_dependencies: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct PackageLock {
    packages: BTreeMap<String, LockedPackage>,
}

#[derive(Debug, Clone, Deserialize)]
struct LockedPackage {
    version: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct ServiceManifest {
    package_name: String,
    dependencies: BTreeSet<String>,
}

pub fn scan_npm_workspace(root: impl AsRef<Path>) -> Result<ScanReport, ScanError> {
    let root = root.as_ref();
    if !root.exists() {
        return Err(ScanError::RootNotFound(root.display().to_string()));
    }

    let root = root.canonicalize().map_err(|source| ScanError::ReadFile {
        path: root.display().to_string(),
        source,
    })?;

    let root_manifest_path = root.join("package.json");
    if !root_manifest_path.exists() {
        return Err(ScanError::MissingRootManifest(
            root_manifest_path.display().to_string(),
        ));
    }

    let lockfile_path = root.join("package-lock.json");
    if !lockfile_path.exists() {
        return Err(ScanError::MissingLockfile(
            lockfile_path.display().to_string(),
        ));
    }

    let root_manifest: PackageManifest = read_json(&root_manifest_path)?;
    let lockfile: PackageLock = read_json(&lockfile_path)?;
    let package_index = build_package_index(&lockfile);
    let workspace_paths = expand_workspaces(&root, root_manifest.workspaces.as_ref())?;

    let mut services = Vec::new();
    for service_path in workspace_paths {
        let manifest_path = service_path.join("package.json");
        let service_manifest = read_service_manifest(&manifest_path)?;
        let dependencies = resolve_dependencies(&service_manifest.dependencies, &package_index);

        services.push(ScannedService {
            name: service_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(&service_manifest.package_name)
                .to_string(),
            path: normalize_path(&relative_path(&root, &service_path)),
            package_name: service_manifest.package_name,
            manifest_path: normalize_path(&relative_path(&root, &manifest_path)),
            lockfile_path: normalize_path(&relative_path(&root, &lockfile_path)),
            dependencies,
        });
    }

    services.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(ScanReport {
        root: root.display().to_string(),
        services,
    })
}

fn read_json<T>(path: &Path) -> Result<T, ScanError>
where
    T: for<'de> Deserialize<'de>,
{
    let raw = fs::read_to_string(path).map_err(|source| ScanError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| ScanError::ParseJson {
        path: path.display().to_string(),
        source,
    })
}

fn read_service_manifest(path: &Path) -> Result<ServiceManifest, ScanError> {
    let manifest: PackageManifest = read_json(path)?;
    let package_name = manifest
        .name
        .ok_or_else(|| ScanError::MissingPackageName(path.display().to_string()))?;

    let dependencies = manifest
        .dependencies
        .keys()
        .chain(manifest.dev_dependencies.keys())
        .cloned()
        .collect();

    Ok(ServiceManifest {
        package_name,
        dependencies,
    })
}

fn expand_workspaces(
    root: &Path,
    workspaces: Option<&Workspaces>,
) -> Result<Vec<PathBuf>, ScanError> {
    let patterns = match workspaces {
        Some(Workspaces::Array(patterns)) => patterns,
        Some(Workspaces::Object { packages }) => packages,
        None => return Err(ScanError::MissingWorkspaces),
    };

    let mut paths = BTreeSet::new();
    for pattern in patterns {
        if let Some(base) = pattern.strip_suffix("/*") {
            let base_path = root.join(base);
            if !base_path.exists() {
                continue;
            }

            for entry in WalkDir::new(&base_path)
                .min_depth(1)
                .max_depth(1)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_dir())
            {
                let candidate = entry.path().to_path_buf();
                if candidate.join("package.json").exists() {
                    paths.insert(candidate);
                }
            }
        } else if !pattern.contains('*') {
            let candidate = root.join(pattern);
            if candidate.join("package.json").exists() {
                paths.insert(candidate);
            }
        } else {
            return Err(ScanError::UnsupportedWorkspacePattern(pattern.clone()));
        }
    }

    Ok(paths.into_iter().collect())
}

fn build_package_index(lockfile: &PackageLock) -> BTreeMap<String, LockedPackage> {
    let mut index = BTreeMap::new();

    for (path, package) in &lockfile.packages {
        if package.version.is_none() {
            continue;
        }

        if let Some(name) = package_name_from_lock_path(path) {
            index.entry(name).or_insert_with(|| package.clone());
        }
    }

    index
}

fn package_name_from_lock_path(path: &str) -> Option<String> {
    let marker = "node_modules/";
    let index = path.rfind(marker)?;
    let name = &path[index + marker.len()..];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn resolve_dependencies(
    direct_names: &BTreeSet<String>,
    package_index: &BTreeMap<String, LockedPackage>,
) -> Vec<Dependency> {
    let mut relationships = BTreeMap::new();
    let mut queue = VecDeque::new();

    for name in direct_names {
        relationships.insert(name.clone(), DependencyRelationship::Direct);
        queue.push_back(name.clone());
    }

    while let Some(name) = queue.pop_front() {
        let Some(package) = package_index.get(&name) else {
            continue;
        };

        for child in package.dependencies.keys() {
            if !relationships.contains_key(child) {
                relationships.insert(child.clone(), DependencyRelationship::Transitive);
                queue.push_back(child.clone());
            }
        }
    }

    relationships
        .into_iter()
        .filter_map(|(name, relationship)| {
            package_index.get(&name).and_then(|package| {
                package.version.as_ref().map(|version| Dependency {
                    name,
                    version: version.clone(),
                    relationship,
                })
            })
        })
        .collect()
}

fn relative_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_scoped_and_unscoped_package_names_from_lock_paths() {
        assert_eq!(
            package_name_from_lock_path("node_modules/lodash"),
            Some("lodash".to_string())
        );
        assert_eq!(
            package_name_from_lock_path("node_modules/@scope/package"),
            Some("@scope/package".to_string())
        );
        assert_eq!(package_name_from_lock_path("apps/api-gateway"), None);
    }

    #[test]
    fn builds_package_index_from_lockfile_packages() {
        let lockfile = PackageLock {
            packages: BTreeMap::from([
                (
                    "".to_string(),
                    LockedPackage {
                        version: None,
                        dependencies: BTreeMap::new(),
                    },
                ),
                (
                    "node_modules/lodash".to_string(),
                    LockedPackage {
                        version: Some("4.17.20".to_string()),
                        dependencies: BTreeMap::new(),
                    },
                ),
            ]),
        };

        let index = build_package_index(&lockfile);

        assert_eq!(
            index
                .get("lodash")
                .and_then(|package| package.version.as_deref()),
            Some("4.17.20")
        );
    }

    #[test]
    fn resolves_direct_and_transitive_dependencies() {
        let direct_names = BTreeSet::from(["mkdirp".to_string()]);
        let package_index = BTreeMap::from([
            (
                "mkdirp".to_string(),
                LockedPackage {
                    version: Some("0.5.1".to_string()),
                    dependencies: BTreeMap::from([("minimist".to_string(), "0.0.8".to_string())]),
                },
            ),
            (
                "minimist".to_string(),
                LockedPackage {
                    version: Some("0.0.8".to_string()),
                    dependencies: BTreeMap::new(),
                },
            ),
        ]);

        let dependencies = resolve_dependencies(&direct_names, &package_index);

        assert_eq!(
            dependencies,
            vec![
                Dependency {
                    name: "minimist".to_string(),
                    version: "0.0.8".to_string(),
                    relationship: DependencyRelationship::Transitive,
                },
                Dependency {
                    name: "mkdirp".to_string(),
                    version: "0.5.1".to_string(),
                    relationship: DependencyRelationship::Direct,
                },
            ]
        );
    }
}
