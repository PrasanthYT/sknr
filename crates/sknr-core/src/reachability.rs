use crate::model::{Dependency, ReachabilityEvidence, ReachabilitySignal};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const MAX_EVIDENCE_PER_PACKAGE: usize = 3;

pub fn apply_reachability_signals(
    root: &Path,
    service_path: &Path,
    dependencies: &mut [Dependency],
) {
    let package_names = dependencies
        .iter()
        .map(|dependency| dependency.name.clone())
        .collect::<Vec<_>>();
    let evidence = collect_import_evidence(root, service_path, &package_names);

    for dependency in dependencies {
        let dependency_evidence = evidence.get(&dependency.name).cloned().unwrap_or_default();
        dependency.reachability = ReachabilitySignal {
            imported: !dependency_evidence.is_empty(),
            evidence: dependency_evidence,
        };
    }
}

fn collect_import_evidence(
    root: &Path,
    service_path: &Path,
    package_names: &[String],
) -> BTreeMap<String, Vec<ReachabilityEvidence>> {
    let mut evidence = package_names
        .iter()
        .map(|name| (name.clone(), Vec::new()))
        .collect::<BTreeMap<_, _>>();

    for entry in WalkDir::new(service_path)
        .into_iter()
        .filter_entry(|entry| entry.file_name() != "node_modules")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| is_source_file(entry.path()))
    {
        let Ok(raw) = fs::read_to_string(entry.path()) else {
            continue;
        };

        for (line_index, line) in raw.lines().enumerate() {
            for package_name in package_names {
                let Some(package_evidence) = evidence.get_mut(package_name) else {
                    continue;
                };
                if package_evidence.len() >= MAX_EVIDENCE_PER_PACKAGE {
                    continue;
                }
                if is_import_line_for_package(line, package_name) {
                    package_evidence.push(ReachabilityEvidence {
                        path: normalize_path(&relative_path(root, entry.path())),
                        line: line_index + 1,
                        snippet: line.trim().to_string(),
                    });
                }
            }
        }
    }

    evidence
}

fn is_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs")
    )
}

fn is_import_line_for_package(line: &str, package_name: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
        return false;
    }

    let double_exact = format!("\"{package_name}\"");
    let single_exact = format!("'{package_name}'");
    let double_subpath = format!("\"{package_name}/");
    let single_subpath = format!("'{package_name}/");

    (trimmed.contains("import ") || trimmed.contains("from ") || trimmed.contains("require("))
        && (trimmed.contains(&double_exact)
            || trimmed.contains(&single_exact)
            || trimmed.contains(&double_subpath)
            || trimmed.contains(&single_subpath))
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
    fn detects_common_import_forms() {
        assert!(is_import_line_for_package(
            "const lodash = require('lodash');",
            "lodash"
        ));
        assert!(is_import_line_for_package(
            "import axios from \"axios\";",
            "axios"
        ));
        assert!(is_import_line_for_package(
            "import thing from '@scope/pkg/subpath';",
            "@scope/pkg"
        ));
    }

    #[test]
    fn ignores_comments_and_unrelated_packages() {
        assert!(!is_import_line_for_package(
            "// const lodash = require('lodash');",
            "lodash"
        ));
        assert!(!is_import_line_for_package(
            "const axios = require('axios');",
            "lodash"
        ));
    }
}
