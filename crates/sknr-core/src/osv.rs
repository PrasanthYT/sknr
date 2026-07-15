use crate::model::{AdvisorySummary, InventoryPackage};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const OSV_QUERY_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

#[derive(Debug, Error)]
pub enum OsvError {
    #[error("failed to query OSV: {0}")]
    Request(#[from] reqwest::Error),
    #[error("OSV returned {results} results for {queries} queries")]
    ResultCountMismatch { queries: usize, results: usize },
}

#[derive(Debug, Serialize)]
struct QueryBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    ecosystem: &'static str,
    name: String,
}

#[derive(Debug, Deserialize)]
struct QueryBatchResponse {
    results: Vec<OsvResult>,
}

#[derive(Debug, Deserialize)]
struct OsvResult {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    modified: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
}

pub async fn enrich_inventory_with_osv(inventory: &mut [InventoryPackage]) -> Result<(), OsvError> {
    if inventory.is_empty() {
        return Ok(());
    }

    let request = QueryBatchRequest {
        queries: inventory
            .iter()
            .map(|package| OsvQuery {
                package: OsvPackage {
                    ecosystem: "npm",
                    name: package.name.clone(),
                },
                version: package.version.clone(),
            })
            .collect(),
    };

    let response = reqwest::Client::new()
        .post(OSV_QUERY_BATCH_URL)
        .json(&request)
        .send()
        .await?
        .error_for_status()?
        .json::<QueryBatchResponse>()
        .await?;

    apply_query_batch_response(inventory, response)
}

fn apply_query_batch_response(
    inventory: &mut [InventoryPackage],
    response: QueryBatchResponse,
) -> Result<(), OsvError> {
    if response.results.len() != inventory.len() {
        return Err(OsvError::ResultCountMismatch {
            queries: inventory.len(),
            results: response.results.len(),
        });
    }

    for (package, result) in inventory.iter_mut().zip(response.results) {
        package.advisories = result
            .vulns
            .into_iter()
            .map(|vuln| AdvisorySummary {
                cve_aliases: vuln
                    .aliases
                    .iter()
                    .filter(|alias| alias.starts_with("CVE-"))
                    .cloned()
                    .collect(),
                id: vuln.id,
                modified: vuln.modified,
                aliases: vuln.aliases,
                kev_match: None,
            })
            .collect();
        package
            .advisories
            .sort_by(|left, right| left.id.cmp(&right.id));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_osv_results_to_inventory_by_response_order() {
        let mut inventory = vec![
            InventoryPackage {
                name: "lodash".to_string(),
                version: "4.17.20".to_string(),
                relationships: Vec::new(),
                used_by: Vec::new(),
                advisories: Vec::new(),
                priority: None,
            },
            InventoryPackage {
                name: "axios".to_string(),
                version: "0.21.0".to_string(),
                relationships: Vec::new(),
                used_by: Vec::new(),
                advisories: Vec::new(),
                priority: None,
            },
        ];
        let response = QueryBatchResponse {
            results: vec![
                OsvResult {
                    vulns: vec![OsvVulnerability {
                        id: "GHSA-lodash".to_string(),
                        modified: Some("2024-01-01T00:00:00Z".to_string()),
                        aliases: vec!["CVE-2021-0001".to_string()],
                    }],
                },
                OsvResult {
                    vulns: vec![OsvVulnerability {
                        id: "GHSA-axios".to_string(),
                        modified: None,
                        aliases: Vec::new(),
                    }],
                },
            ],
        };

        apply_query_batch_response(&mut inventory, response).unwrap();

        assert_eq!(inventory[0].advisories[0].id, "GHSA-lodash");
        assert_eq!(inventory[1].advisories[0].id, "GHSA-axios");
    }
}
