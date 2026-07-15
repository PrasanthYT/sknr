use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedConfig {
    pub services: Vec<GeneratedService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedService {
    pub name: String,
    pub path: String,
    pub internet_facing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitSummary {
    pub path: String,
    pub services: Vec<GeneratedService>,
    pub overwritten: bool,
}

#[derive(Debug, Error)]
pub enum InitError {
    #[error("missing root package.json: {0}")]
    MissingRootManifest(String),
    #[error("sknr config already exists: {0}; pass --force to overwrite")]
    ConfigExists(String),
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
    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: String,
        source: std::io::Error,
    },
    #[error("root package.json does not declare npm workspaces")]
    MissingWorkspaces,
    #[error("workspace pattern is unsupported: {0}")]
    UnsupportedWorkspacePattern(String),
    #[error("workspace package is missing a name: {0}")]
    MissingPackageName(String),
    #[error("failed to serialize config: {0}")]
    SerializeYaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Workspaces {
    Array(Vec<String>),
    Object { packages: Vec<String> },
}

#[derive(Debug, Deserialize)]
struct PackageManifest {
    name: Option<String>,
    workspaces: Option<Workspaces>,
}

pub fn generate_sknr_config(root: impl AsRef<Path>, force: bool) -> Result<InitSummary, InitError> {
    let root = root.as_ref();
    let root_manifest_path = root.join("package.json");
    if !root_manifest_path.exists() {
        return Err(InitError::MissingRootManifest(
            root_manifest_path.display().to_string(),
        ));
    }

    let config_path = root.join("sknr.config.yaml");
    let overwritten = config_path.exists();
    if overwritten && !force {
        return Err(InitError::ConfigExists(config_path.display().to_string()));
    }

    let root_manifest: PackageManifest = read_json(&root_manifest_path)?;
    let service_paths = expand_workspaces(root, root_manifest.workspaces.as_ref())?;
    let mut services = Vec::new();
    for service_path in service_paths {
        let manifest_path = service_path.join("package.json");
        let manifest: PackageManifest = read_json(&manifest_path)?;
        let name = manifest
            .name
            .ok_or_else(|| InitError::MissingPackageName(manifest_path.display().to_string()))?;
        let path = normalize_path(&relative_path(root, &service_path));
        services.push(GeneratedService {
            name: service_name(&name, root, &service_path),
            path,
            internet_facing: false,
        });
    }

    let config = GeneratedConfig {
        services: services.clone(),
    };
    let yaml = serde_yaml::to_string(&config)?;
    fs::write(&config_path, yaml).map_err(|source| InitError::WriteFile {
        path: config_path.display().to_string(),
        source,
    })?;

    Ok(InitSummary {
        path: config_path.display().to_string(),
        services,
        overwritten,
    })
}

fn read_json<T>(path: &Path) -> Result<T, InitError>
where
    T: for<'de> Deserialize<'de>,
{
    let raw = fs::read_to_string(path).map_err(|source| InitError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| InitError::ParseJson {
        path: path.display().to_string(),
        source,
    })
}

fn expand_workspaces(
    root: &Path,
    workspaces: Option<&Workspaces>,
) -> Result<Vec<PathBuf>, InitError> {
    let patterns = match workspaces {
        Some(Workspaces::Array(patterns)) => patterns,
        Some(Workspaces::Object { packages }) => packages,
        None => return Ok(vec![root.to_path_buf()]),
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
            return Err(InitError::UnsupportedWorkspacePattern(pattern.clone()));
        }
    }
    Ok(paths.into_iter().collect())
}

fn service_name(package_name: &str, root: &Path, service_path: &Path) -> String {
    if service_path == root {
        return package_name.to_string();
    }

    service_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| package_name.to_string())
}

fn relative_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn normalize_path(path: &Path) -> String {
    let normalized = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    if normalized.is_empty() {
        ".".to_string()
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_config_for_single_package_repo() {
        let root = std::env::temp_dir().join(format!("sknr-init-single-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"name":"ezhupira","dependencies":{"lodash":"4.17.20"}}"#,
        )
        .unwrap();

        let summary = generate_sknr_config(&root, false).unwrap();

        assert_eq!(summary.services.len(), 1);
        assert_eq!(summary.services[0].name, "ezhupira");
        assert_eq!(summary.services[0].path, ".");
        assert!(root.join("sknr.config.yaml").exists());

        let _ = fs::remove_dir_all(root);
    }
}
