use crate::model::{DependencyRelationship, InventoryPackage, PriorityAssessment, PriorityBucket};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

const OPENAI_RESPONSES_URL: &str = "https://api.openai.com/v1/responses";

#[derive(Debug, Clone)]
pub struct AiPriorityOptions {
    pub api_key: String,
    pub model: String,
}

#[derive(Debug, Error)]
pub enum PriorityError {
    #[error("failed to query OpenAI priority model: {0}")]
    Request(#[from] reqwest::Error),
    #[error("failed to parse OpenAI priority response: {0}")]
    Json(#[from] serde_json::Error),
    #[error("OpenAI response did not include output text")]
    MissingOutputText,
}

#[derive(Debug, Clone, Serialize)]
struct PriorityRequestPayload {
    findings: Vec<PriorityFindingInput>,
}

#[derive(Debug, Clone, Serialize)]
struct PriorityFindingInput {
    package: String,
    version: String,
    advisory_count: usize,
    advisory_ids: Vec<String>,
    cve_aliases: Vec<String>,
    has_kev_match: bool,
    direct_services: Vec<String>,
    transitive_services: Vec<String>,
    reachable_services: Vec<String>,
    internet_facing_services: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PriorityModelResponse {
    findings: Vec<PriorityFindingOutput>,
}

#[derive(Debug, Deserialize)]
struct PriorityFindingOutput {
    package: String,
    version: String,
    bucket: PriorityBucket,
    reasons: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    output: Vec<OpenAiOutputItem>,
}

#[derive(Debug, Deserialize)]
struct OpenAiOutputItem {
    #[serde(default)]
    content: Vec<OpenAiContentItem>,
}

#[derive(Debug, Deserialize)]
struct OpenAiContentItem {
    #[serde(rename = "type")]
    content_type: String,
    text: Option<String>,
}

pub async fn prioritize_inventory_with_openai(
    inventory: &mut [InventoryPackage],
    options: &AiPriorityOptions,
) -> Result<(), PriorityError> {
    let payload = build_priority_payload(inventory);
    if payload.findings.is_empty() {
        return Ok(());
    }

    let response = reqwest::Client::new()
        .post(OPENAI_RESPONSES_URL)
        .bearer_auth(&options.api_key)
        .json(&build_openai_request(&options.model, &payload)?)
        .send()
        .await?
        .error_for_status()?
        .json::<OpenAiResponse>()
        .await?;

    let output_text = extract_output_text(response)?;
    let priority_response: PriorityModelResponse = serde_json::from_str(&output_text)?;
    apply_priority_response(inventory, priority_response, &options.model);

    Ok(())
}

fn build_priority_payload(inventory: &[InventoryPackage]) -> PriorityRequestPayload {
    PriorityRequestPayload {
        findings: inventory
            .iter()
            .filter(|package| !package.advisories.is_empty())
            .map(|package| {
                let advisory_ids = package
                    .advisories
                    .iter()
                    .map(|advisory| advisory.id.clone())
                    .collect::<Vec<_>>();
                let cve_aliases = package
                    .advisories
                    .iter()
                    .flat_map(|advisory| advisory.cve_aliases.clone())
                    .collect::<Vec<_>>();
                let has_kev_match = package
                    .advisories
                    .iter()
                    .any(|advisory| advisory.kev_match.is_some());
                let mut direct_services = Vec::new();
                let mut transitive_services = Vec::new();
                let mut reachable_services = Vec::new();
                let mut internet_facing_services = Vec::new();

                for usage in &package.used_by {
                    match usage.relationship {
                        DependencyRelationship::Direct => {
                            direct_services.push(usage.service.clone())
                        }
                        DependencyRelationship::Transitive => {
                            transitive_services.push(usage.service.clone())
                        }
                    }
                    if usage.reachability.imported {
                        reachable_services.push(usage.service.clone());
                    }
                    if usage.internet_facing {
                        internet_facing_services.push(usage.service.clone());
                    }
                }

                PriorityFindingInput {
                    package: package.name.clone(),
                    version: package.version.clone(),
                    advisory_count: package.advisories.len(),
                    advisory_ids,
                    cve_aliases,
                    has_kev_match,
                    direct_services,
                    transitive_services,
                    reachable_services,
                    internet_facing_services,
                }
            })
            .collect(),
    }
}

fn build_openai_request(
    model: &str,
    payload: &PriorityRequestPayload,
) -> Result<serde_json::Value, PriorityError> {
    Ok(serde_json::json!({
        "model": model,
        "input": [
            {
                "role": "system",
                "content": "You prioritize dependency vulnerability findings for a self-hosted SCA tool. Return only the required JSON. Use buckets exactly: fix_now, this_sprint, monitor. Reasons must be short and traceable to the supplied fields. Do not invent severity, exploit status, or confidence scores."
            },
            {
                "role": "user",
                "content": serde_json::to_string(payload)?
            }
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "sknr_priority_response",
                "strict": true,
                "schema": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "package": { "type": "string" },
                                    "version": { "type": "string" },
                                    "bucket": {
                                        "type": "string",
                                        "enum": ["fix_now", "this_sprint", "monitor"]
                                    },
                                    "reasons": {
                                        "type": "array",
                                        "items": { "type": "string" }
                                    }
                                },
                                "required": ["package", "version", "bucket", "reasons"],
                                "additionalProperties": false
                            }
                        }
                    },
                    "required": ["findings"],
                    "additionalProperties": false
                }
            }
        }
    }))
}

fn extract_output_text(response: OpenAiResponse) -> Result<String, PriorityError> {
    response
        .output
        .into_iter()
        .flat_map(|item| item.content)
        .find(|content| content.content_type == "output_text")
        .and_then(|content| content.text)
        .ok_or(PriorityError::MissingOutputText)
}

fn apply_priority_response(
    inventory: &mut [InventoryPackage],
    response: PriorityModelResponse,
    model: &str,
) {
    let assessments = response
        .findings
        .into_iter()
        .map(|finding| ((finding.package.clone(), finding.version.clone()), finding))
        .collect::<BTreeMap<_, _>>();

    for package in inventory {
        if let Some(finding) = assessments.get(&(package.name.clone(), package.version.clone())) {
            package.priority = Some(PriorityAssessment {
                bucket: finding.bucket,
                reasons: finding.reasons.clone(),
                model: model.to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AdvisorySummary, DependencyRelationship, PackageUsage, ReachabilitySignal};

    #[test]
    fn builds_priority_payload_for_advisory_packages_only() {
        let inventory = vec![
            InventoryPackage {
                name: "lodash".to_string(),
                version: "4.17.20".to_string(),
                relationships: vec![DependencyRelationship::Direct],
                used_by: vec![PackageUsage {
                    service: "api-gateway".to_string(),
                    relationship: DependencyRelationship::Direct,
                    internet_facing: true,
                    reachability: ReachabilitySignal {
                        imported: true,
                        evidence: Vec::new(),
                    },
                }],
                advisories: vec![AdvisorySummary {
                    id: "GHSA-demo".to_string(),
                    modified: None,
                    aliases: vec!["CVE-2021-23337".to_string()],
                    cve_aliases: vec!["CVE-2021-23337".to_string()],
                    kev_match: None,
                }],
                priority: None,
            },
            InventoryPackage {
                name: "safe".to_string(),
                version: "1.0.0".to_string(),
                relationships: Vec::new(),
                used_by: Vec::new(),
                advisories: Vec::new(),
                priority: None,
            },
        ];

        let payload = build_priority_payload(&inventory);

        assert_eq!(payload.findings.len(), 1);
        assert_eq!(payload.findings[0].package, "lodash");
        assert_eq!(payload.findings[0].reachable_services, vec!["api-gateway"]);
    }

    #[test]
    fn applies_priority_response_to_matching_packages() {
        let mut inventory = vec![InventoryPackage {
            name: "lodash".to_string(),
            version: "4.17.20".to_string(),
            relationships: Vec::new(),
            used_by: Vec::new(),
            advisories: Vec::new(),
            priority: None,
        }];
        let response = PriorityModelResponse {
            findings: vec![PriorityFindingOutput {
                package: "lodash".to_string(),
                version: "4.17.20".to_string(),
                bucket: PriorityBucket::FixNow,
                reasons: vec!["reachable direct dependency".to_string()],
            }],
        };

        apply_priority_response(&mut inventory, response, "gpt-5.6");

        assert_eq!(
            inventory[0]
                .priority
                .as_ref()
                .map(|priority| priority.bucket),
            Some(PriorityBucket::FixNow)
        );
    }
}
