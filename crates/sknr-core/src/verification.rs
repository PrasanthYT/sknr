use crate::model::ScanReport;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub before_vulnerable_packages: usize,
    pub after_vulnerable_packages: usize,
    pub before_advisories: usize,
    pub after_advisories: usize,
    pub fixed_packages: Vec<FixedPackage>,
    pub risk_reduced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedPackage {
    pub package: String,
    pub before_version: String,
    pub after_version: Option<String>,
    pub before_advisories: usize,
    pub after_advisories: usize,
}

pub fn verify_scan_reduction(before: &ScanReport, after: &ScanReport) -> VerificationReport {
    let before_packages = package_map(before);
    let after_packages = package_map(after);
    let mut fixed_packages = Vec::new();

    for (name, before_package) in &before_packages {
        if before_package.advisory_count == 0 {
            continue;
        }

        let after_package = after_packages.get(name);
        let after_advisories = after_package
            .map(|package| package.advisory_count)
            .unwrap_or_default();
        let after_version = after_package.map(|package| package.version.clone());

        if after_advisories < before_package.advisory_count
            || after_version.as_ref() != Some(&before_package.version)
        {
            fixed_packages.push(FixedPackage {
                package: name.clone(),
                before_version: before_package.version.clone(),
                after_version,
                before_advisories: before_package.advisory_count,
                after_advisories,
            });
        }
    }

    let before_vulnerable_packages = count_vulnerable_packages(before);
    let after_vulnerable_packages = count_vulnerable_packages(after);
    let before_advisories = count_advisories(before);
    let after_advisories = count_advisories(after);

    VerificationReport {
        before_vulnerable_packages,
        after_vulnerable_packages,
        before_advisories,
        after_advisories,
        risk_reduced: after_vulnerable_packages < before_vulnerable_packages
            || after_advisories < before_advisories
            || !fixed_packages.is_empty(),
        fixed_packages,
    }
}

#[derive(Debug, Clone)]
struct PackageSnapshot {
    version: String,
    advisory_count: usize,
}

fn package_map(report: &ScanReport) -> BTreeMap<String, PackageSnapshot> {
    report
        .inventory
        .iter()
        .map(|package| {
            (
                package.name.clone(),
                PackageSnapshot {
                    version: package.version.clone(),
                    advisory_count: package.advisories.len(),
                },
            )
        })
        .collect()
}

fn count_vulnerable_packages(report: &ScanReport) -> usize {
    report
        .inventory
        .iter()
        .filter(|package| !package.advisories.is_empty())
        .count()
}

fn count_advisories(report: &ScanReport) -> usize {
    report
        .inventory
        .iter()
        .map(|package| package.advisories.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{InventoryPackage, ScanReport, ServiceTopology};

    fn report(version: &str, advisories: usize) -> ScanReport {
        ScanReport {
            root: "root".to_string(),
            topology: ServiceTopology {
                nodes: Vec::new(),
                edges: Vec::new(),
            },
            inventory: vec![InventoryPackage {
                name: "lodash".to_string(),
                version: version.to_string(),
                relationships: Vec::new(),
                used_by: Vec::new(),
                advisories: (0..advisories)
                    .map(|index| crate::model::AdvisorySummary {
                        id: format!("GHSA-{index}"),
                        modified: None,
                        aliases: Vec::new(),
                        cve_aliases: Vec::new(),
                        kev_match: None,
                    })
                    .collect(),
                priority: None,
            }],
            services: Vec::new(),
        }
    }

    #[test]
    fn detects_advisory_reduction() {
        let before = report("4.17.20", 2);
        let after = report("4.17.21", 0);

        let verification = verify_scan_reduction(&before, &after);

        assert!(verification.risk_reduced);
        assert_eq!(verification.before_advisories, 2);
        assert_eq!(verification.after_advisories, 0);
        assert_eq!(verification.fixed_packages[0].package, "lodash");
    }
}
