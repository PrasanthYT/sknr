use crate::model::{InventoryPackage, PriorityBucket, ScanReport};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";
const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub package: String,
    pub current_version: String,
    pub target_version: String,
    pub services: Vec<String>,
    pub priority_bucket: PriorityBucket,
    pub upgrade_risk: UpgradeRisk,
    pub reasons: Vec<String>,
    pub codex_task: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeRisk {
    Patch,
    Minor,
    Major,
}

#[derive(Debug, Error)]
pub enum RemediationError {
    #[error("failed to query npm registry or OSV: {0}")]
    Request(#[from] reqwest::Error),
    #[error("failed to parse npm or OSV response: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid current semver version for {package}: {version}")]
    InvalidCurrentVersion { package: String, version: String },
    #[error("no safe upgrade version found for {package}@{version}")]
    NoSafeVersion { package: String, version: String },
}

#[derive(Debug, Deserialize)]
struct NpmPackument {
    versions: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, serde::Serialize)]
struct OsvQueryRequest {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, serde::Serialize)]
struct OsvPackage {
    ecosystem: &'static str,
    name: String,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<serde_json::Value>,
}

pub async fn build_remediation_plans(
    report: &ScanReport,
) -> Result<Vec<RemediationPlan>, RemediationError> {
    let mut plans = Vec::new();

    for package in report
        .inventory
        .iter()
        .filter(|package| should_plan(package))
    {
        let current_version = Version::parse(&package.version).map_err(|_| {
            RemediationError::InvalidCurrentVersion {
                package: package.name.clone(),
                version: package.version.clone(),
            }
        })?;
        let target_version = find_nearest_safe_version(&package.name, &current_version).await?;
        let priority_bucket = planning_bucket(package);
        let upgrade_risk = classify_upgrade_risk(&current_version, &target_version);
        let services = package
            .used_by
            .iter()
            .map(|usage| usage.service.clone())
            .collect::<Vec<_>>();
        let reasons = build_plan_reasons(package, &target_version, upgrade_risk);
        let codex_task = build_codex_task(
            &package.name,
            &package.version,
            &target_version.to_string(),
            &services,
        );

        plans.push(RemediationPlan {
            package: package.name.clone(),
            current_version: package.version.clone(),
            target_version: target_version.to_string(),
            services,
            priority_bucket,
            upgrade_risk,
            reasons,
            codex_task,
        });
    }

    Ok(plans)
}

pub fn build_codex_task(
    package: &str,
    current_version: &str,
    target_version: &str,
    services: &[String],
) -> String {
    format!(
        "Update npm dependency `{package}` from `{current_version}` to `{target_version}` in the Sknr demo monorepo.\n\nScope:\n- Repository root: current working directory.\n- Fixture root: `fixtures/demo-monorepo`.\n- Affected services: {services}.\n\nRequired work:\n1. Update the relevant `package.json` dependency declaration(s) to `{target_version}`.\n2. Run `npm install --package-lock-only` in `fixtures/demo-monorepo` to update `package-lock.json`.\n3. Run `npm test` in `fixtures/demo-monorepo`.\n4. Keep changes limited to the fixture dependency bump and lockfile update.\n\nReturn a concise summary of changed files and command results.",
        services = services.join(", ")
    )
}

pub fn classify_upgrade_risk(current: &Version, target: &Version) -> UpgradeRisk {
    if target.major != current.major {
        UpgradeRisk::Major
    } else if target.minor != current.minor {
        UpgradeRisk::Minor
    } else {
        UpgradeRisk::Patch
    }
}

fn should_plan(package: &InventoryPackage) -> bool {
    if package.advisories.is_empty() {
        return false;
    }

    !matches!(
        package.priority.as_ref().map(|priority| priority.bucket),
        Some(PriorityBucket::Monitor)
    )
}

fn planning_bucket(package: &InventoryPackage) -> PriorityBucket {
    package
        .priority
        .as_ref()
        .map(|priority| priority.bucket)
        .unwrap_or(PriorityBucket::ThisSprint)
}

fn build_plan_reasons(
    package: &InventoryPackage,
    target_version: &Version,
    upgrade_risk: UpgradeRisk,
) -> Vec<String> {
    let mut reasons = package
        .priority
        .as_ref()
        .map(|priority| priority.reasons.clone())
        .unwrap_or_else(|| {
            vec![
                "advisory-backed finding without AI bucket; defaulting to this_sprint for planning"
                    .to_string(),
            ]
        });

    reasons.push(format!(
        "nearest safe npm version selected: {target_version}"
    ));
    reasons.push(format!("upgrade risk classified as {upgrade_risk:?}"));
    reasons
}

async fn find_nearest_safe_version(
    package: &str,
    current: &Version,
) -> Result<Version, RemediationError> {
    let packument = fetch_npm_packument(package).await?;
    let mut candidates = packument
        .versions
        .keys()
        .filter_map(|version| Version::parse(version).ok())
        .filter(|version| version > current)
        .collect::<Vec<_>>();
    candidates.sort();

    for candidate in candidates {
        if is_version_safe(package, &candidate).await? {
            return Ok(candidate);
        }
    }

    Err(RemediationError::NoSafeVersion {
        package: package.to_string(),
        version: current.to_string(),
    })
}

async fn fetch_npm_packument(package: &str) -> Result<NpmPackument, RemediationError> {
    let package_path = package.replace('@', "%40").replace('/', "%2F");
    Ok(reqwest::Client::new()
        .get(format!("{NPM_REGISTRY_URL}/{package_path}"))
        .send()
        .await?
        .error_for_status()?
        .json::<NpmPackument>()
        .await?)
}

async fn is_version_safe(package: &str, version: &Version) -> Result<bool, RemediationError> {
    let response = reqwest::Client::new()
        .post(OSV_QUERY_URL)
        .json(&OsvQueryRequest {
            package: OsvPackage {
                ecosystem: "npm",
                name: package.to_string(),
            },
            version: version.to_string(),
        })
        .send()
        .await?
        .error_for_status()?
        .json::<OsvQueryResponse>()
        .await?;

    Ok(response.vulns.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PriorityAssessment, PriorityBucket};

    #[test]
    fn classifies_semver_upgrade_risk() {
        assert_eq!(
            classify_upgrade_risk(
                &Version::parse("1.2.3").unwrap(),
                &Version::parse("1.2.4").unwrap()
            ),
            UpgradeRisk::Patch
        );
        assert_eq!(
            classify_upgrade_risk(
                &Version::parse("1.2.3").unwrap(),
                &Version::parse("1.3.0").unwrap()
            ),
            UpgradeRisk::Minor
        );
        assert_eq!(
            classify_upgrade_risk(
                &Version::parse("1.2.3").unwrap(),
                &Version::parse("2.0.0").unwrap()
            ),
            UpgradeRisk::Major
        );
    }

    #[test]
    fn planner_includes_fix_now_and_this_sprint_only() {
        let fix_now = InventoryPackage {
            name: "lodash".to_string(),
            version: "4.17.20".to_string(),
            relationships: Vec::new(),
            used_by: Vec::new(),
            advisories: vec![crate::model::AdvisorySummary {
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
        };
        let mut monitor = fix_now.clone();
        monitor.name = "monitor".to_string();
        monitor.priority = Some(PriorityAssessment {
            bucket: PriorityBucket::Monitor,
            reasons: Vec::new(),
            model: "test".to_string(),
        });
        let mut safe = fix_now.clone();
        safe.name = "safe".to_string();
        safe.advisories = Vec::new();

        assert!(should_plan(&fix_now));
        assert!(!should_plan(&monitor));
        assert!(!should_plan(&safe));
    }

    #[test]
    fn codex_task_contains_patch_commands_and_target() {
        let task = build_codex_task("lodash", "4.17.20", "4.17.21", &["api-gateway".to_string()]);

        assert!(task.contains("lodash"));
        assert!(task.contains("4.17.21"));
        assert!(task.contains("npm install --package-lock-only"));
        assert!(task.contains("npm test"));
    }
}
