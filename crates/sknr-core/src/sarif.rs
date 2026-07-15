use crate::model::{InventoryPackage, PriorityBucket, ScanReport};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub fn render_sarif(report: &ScanReport) -> Value {
    let mut rules = BTreeMap::<String, Value>::new();
    let mut results = Vec::new();

    for package in report
        .inventory
        .iter()
        .filter(|package| !package.advisories.is_empty())
    {
        for advisory in &package.advisories {
            rules.entry(advisory.id.clone()).or_insert_with(|| {
                json!({
                    "id": advisory.id,
                    "name": advisory.id,
                    "shortDescription": {
                        "text": format!("{} affects npm package {}", advisory.id, package.name)
                    },
                    "helpUri": format!("https://osv.dev/vulnerability/{}", advisory.id),
                    "properties": {
                        "aliases": advisory.aliases,
                        "cveAliases": advisory.cve_aliases,
                        "kevMatch": advisory.kev_match
                    }
                })
            });

            for usage in &package.used_by {
                results.push(json!({
                    "ruleId": advisory.id,
                    "level": sarif_level(package),
                    "message": {
                        "text": format!(
                            "{}@{} is used by {} and has advisory {}",
                            package.name, package.version, usage.service, advisory.id
                        )
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": usage
                                    .reachability
                                    .evidence
                                    .first()
                                    .map(|evidence| evidence.path.as_str())
                                    .unwrap_or(&report.root)
                            },
                            "region": {
                                "startLine": usage
                                    .reachability
                                    .evidence
                                    .first()
                                    .map(|evidence| evidence.line)
                                    .unwrap_or(1)
                            }
                        }
                    }],
                    "properties": {
                        "package": package.name,
                        "version": package.version,
                        "service": usage.service,
                        "relationship": usage.relationship,
                        "internetFacing": usage.internet_facing,
                        "reachable": usage.reachability.imported,
                        "priority": package.priority.as_ref().map(|priority| priority.bucket)
                    }
                }));
            }
        }
    }

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Sknr",
                    "informationUri": "https://github.com/sknr/sknr",
                    "rules": rules.into_values().collect::<Vec<_>>()
                }
            },
            "results": results
        }]
    })
}

fn sarif_level(package: &InventoryPackage) -> &'static str {
    match package.priority.as_ref().map(|priority| priority.bucket) {
        Some(PriorityBucket::FixNow) => "error",
        Some(PriorityBucket::Monitor) => "note",
        Some(PriorityBucket::ThisSprint) | None => "warning",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AdvisorySummary, InventoryPackage, PackageUsage, PriorityAssessment, ReachabilitySignal,
        ScanReport, ServiceTopology,
    };

    #[test]
    fn renders_sarif_for_advisory_packages() {
        let report = ScanReport {
            root: "/repo".to_string(),
            topology: ServiceTopology {
                nodes: Vec::new(),
                edges: Vec::new(),
            },
            services: Vec::new(),
            inventory: vec![InventoryPackage {
                name: "lodash".to_string(),
                version: "4.17.20".to_string(),
                relationships: Vec::new(),
                used_by: vec![PackageUsage {
                    service: "api".to_string(),
                    relationship: crate::model::DependencyRelationship::Direct,
                    internet_facing: true,
                    reachability: ReachabilitySignal::not_found(),
                }],
                advisories: vec![AdvisorySummary {
                    id: "GHSA-demo".to_string(),
                    modified: None,
                    aliases: Vec::new(),
                    cve_aliases: Vec::new(),
                    kev_match: None,
                }],
                priority: Some(PriorityAssessment {
                    bucket: PriorityBucket::FixNow,
                    reasons: Vec::new(),
                    model: "test".to_string(),
                }),
            }],
        };

        let sarif = render_sarif(&report);

        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");
    }
}
