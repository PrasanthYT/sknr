use crate::model::{DependencyRelationship, InventoryPackage, ScanReport};
use serde_json::{json, Value};

pub fn render_cyclonedx_json(report: &ScanReport) -> Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "sknr-scan",
                "version": "0.1.0"
            },
            "properties": [
                {"name": "sknr:root", "value": report.root}
            ]
        },
        "components": report
            .inventory
            .iter()
            .map(component)
            .collect::<Vec<_>>()
    })
}

fn component(package: &InventoryPackage) -> Value {
    json!({
        "type": "library",
        "bom-ref": package_ref(package),
        "name": package.name,
        "version": package.version,
        "purl": package_purl(package),
        "properties": [
            {
                "name": "sknr:relationships",
                "value": package.relationships.iter().map(relationship).collect::<Vec<_>>().join(",")
            },
            {
                "name": "sknr:services",
                "value": package.used_by.iter().map(|usage| usage.service.as_str()).collect::<Vec<_>>().join(",")
            },
            {
                "name": "sknr:advisories",
                "value": package.advisories.iter().map(|advisory| advisory.id.as_str()).collect::<Vec<_>>().join(",")
            }
        ],
        "externalReferences": package
            .advisories
            .iter()
            .map(|advisory| {
                json!({
                    "type": "advisories",
                    "url": format!("https://osv.dev/vulnerability/{}", advisory.id),
                    "comment": advisory.id
                })
            })
            .collect::<Vec<_>>()
    })
}

fn package_ref(package: &InventoryPackage) -> String {
    format!(
        "pkg:npm/{}@{}",
        encode_purl_name(&package.name),
        package.version
    )
}

fn package_purl(package: &InventoryPackage) -> String {
    package_ref(package)
}

fn encode_purl_name(name: &str) -> String {
    name.replace('@', "%40")
}

fn relationship(relationship: &DependencyRelationship) -> &'static str {
    match relationship {
        DependencyRelationship::Direct => "direct",
        DependencyRelationship::Transitive => "transitive",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{InventoryPackage, ScanReport, ServiceTopology};

    #[test]
    fn renders_cyclonedx_components() {
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
                used_by: Vec::new(),
                advisories: Vec::new(),
                priority: None,
            }],
        };

        let bom = render_cyclonedx_json(&report);

        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["components"][0]["name"], "lodash");
    }
}
