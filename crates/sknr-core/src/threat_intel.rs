use crate::model::{AdvisorySummary, InventoryPackage, KevMatch};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const OSV_QUERY_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns";
const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const CACHE_TTL_SECONDS: i64 = 24 * 60 * 60;
const CISA_CACHE_KEY: &str = "cisa_kev_feed";

#[derive(Debug, Clone)]
pub struct ThreatIntelOptions {
    pub cache_path: PathBuf,
    pub refresh_cache: bool,
}

#[derive(Debug, Error)]
pub enum ThreatIntelError {
    #[error("failed to initialize cache directory {path}: {source}")]
    CreateCacheDirectory {
        path: String,
        source: std::io::Error,
    },
    #[error("cache error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("failed to query threat-intel source: {0}")]
    Request(#[from] reqwest::Error),
    #[error("failed to parse threat-intel JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("OSV returned {results} results for {queries} queries")]
    OsvResultCountMismatch { queries: usize, results: usize },
    #[error("system clock is before UNIX epoch")]
    InvalidSystemTime,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OsvResult {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OsvVulnerability {
    id: String,
    modified: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CisaKevCatalog {
    #[serde(default)]
    vulnerabilities: Vec<CisaKevVulnerability>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CisaKevVulnerability {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vulnerabilityName")]
    vulnerability_name: String,
    #[serde(rename = "dateAdded")]
    date_added: String,
    #[serde(rename = "dueDate")]
    due_date: String,
    #[serde(rename = "knownRansomwareCampaignUse")]
    known_ransomware_campaign_use: String,
}

pub async fn enrich_inventory_with_threat_intel(
    inventory: &mut [InventoryPackage],
    options: &ThreatIntelOptions,
) -> Result<(), ThreatIntelError> {
    if inventory.is_empty() {
        return Ok(());
    }

    let cache = ThreatIntelCache::open(&options.cache_path)?;
    let now = current_unix_timestamp()?;
    let kev_index = cache.get_cisa_kev_index(options.refresh_cache, now).await?;
    let osv_results = cache
        .get_osv_results(inventory, options.refresh_cache, now)
        .await?;

    apply_osv_and_kev_results(inventory, osv_results, &kev_index);

    Ok(())
}

struct ThreatIntelCache {
    connection: Connection,
}

impl ThreatIntelCache {
    fn open(path: &Path) -> Result<Self, ThreatIntelError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| {
                ThreatIntelError::CreateCacheDirectory {
                    path: parent.display().to_string(),
                    source,
                }
            })?;
        }

        let connection = Connection::open(path)?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS osv_cache (
                package_name TEXT NOT NULL,
                version TEXT NOT NULL,
                response_json TEXT NOT NULL,
                fetched_at INTEGER NOT NULL,
                PRIMARY KEY (package_name, version)
            );

            CREATE TABLE IF NOT EXISTS metadata_cache (
                cache_key TEXT PRIMARY KEY,
                response_json TEXT NOT NULL,
                fetched_at INTEGER NOT NULL
            );
            ",
        )?;

        Ok(Self { connection })
    }

    async fn get_osv_results(
        &self,
        inventory: &[InventoryPackage],
        refresh_cache: bool,
        now: i64,
    ) -> Result<Vec<OsvResult>, ThreatIntelError> {
        let mut results = vec![None; inventory.len()];
        let mut misses = Vec::new();

        for (index, package) in inventory.iter().enumerate() {
            if !refresh_cache {
                if let Some(result) =
                    self.get_cached_osv_result(&package.name, &package.version, now)?
                {
                    results[index] = Some(result);
                    continue;
                }
            }

            misses.push((index, package.name.clone(), package.version.clone()));
        }

        if !misses.is_empty() {
            let fetched = fetch_osv_batch(&misses).await?;
            for ((index, name, version), result) in misses.into_iter().zip(fetched) {
                self.put_osv_result(&name, &version, &result, now)?;
                results[index] = Some(result);
            }
        }

        Ok(results
            .into_iter()
            .map(|result| result.unwrap_or_else(|| OsvResult { vulns: Vec::new() }))
            .collect())
    }

    fn get_cached_osv_result(
        &self,
        package_name: &str,
        version: &str,
        now: i64,
    ) -> Result<Option<OsvResult>, ThreatIntelError> {
        let cached = self
            .connection
            .query_row(
                "
                SELECT response_json, fetched_at
                FROM osv_cache
                WHERE package_name = ?1 AND version = ?2
                ",
                params![package_name, version],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;

        let Some((response_json, fetched_at)) = cached else {
            return Ok(None);
        };

        if now - fetched_at > CACHE_TTL_SECONDS {
            return Ok(None);
        }

        Ok(Some(serde_json::from_str(&response_json)?))
    }

    fn put_osv_result(
        &self,
        package_name: &str,
        version: &str,
        result: &OsvResult,
        now: i64,
    ) -> Result<(), ThreatIntelError> {
        self.connection.execute(
            "
            INSERT INTO osv_cache (package_name, version, response_json, fetched_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(package_name, version)
            DO UPDATE SET response_json = excluded.response_json, fetched_at = excluded.fetched_at
            ",
            params![package_name, version, serde_json::to_string(result)?, now],
        )?;
        Ok(())
    }

    async fn get_cisa_kev_index(
        &self,
        refresh_cache: bool,
        now: i64,
    ) -> Result<BTreeMap<String, CisaKevVulnerability>, ThreatIntelError> {
        if !refresh_cache {
            if let Some(catalog) = self.get_cached_cisa_kev(now)? {
                return Ok(index_cisa_kev(catalog));
            }
        }

        let catalog = fetch_cisa_kev().await?;
        self.put_cisa_kev(&catalog, now)?;
        Ok(index_cisa_kev(catalog))
    }

    fn get_cached_cisa_kev(&self, now: i64) -> Result<Option<CisaKevCatalog>, ThreatIntelError> {
        let cached = self
            .connection
            .query_row(
                "
                SELECT response_json, fetched_at
                FROM metadata_cache
                WHERE cache_key = ?1
                ",
                params![CISA_CACHE_KEY],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;

        let Some((response_json, fetched_at)) = cached else {
            return Ok(None);
        };

        if now - fetched_at > CACHE_TTL_SECONDS {
            return Ok(None);
        }

        Ok(Some(serde_json::from_str(&response_json)?))
    }

    fn put_cisa_kev(&self, catalog: &CisaKevCatalog, now: i64) -> Result<(), ThreatIntelError> {
        self.connection.execute(
            "
            INSERT INTO metadata_cache (cache_key, response_json, fetched_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(cache_key)
            DO UPDATE SET response_json = excluded.response_json, fetched_at = excluded.fetched_at
            ",
            params![CISA_CACHE_KEY, serde_json::to_string(catalog)?, now],
        )?;
        Ok(())
    }
}

async fn fetch_osv_batch(
    requests: &[(usize, String, String)],
) -> Result<Vec<OsvResult>, ThreatIntelError> {
    let request = QueryBatchRequest {
        queries: requests
            .iter()
            .map(|(_, name, version)| OsvQuery {
                package: OsvPackage {
                    ecosystem: "npm",
                    name: name.clone(),
                },
                version: version.clone(),
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

    if response.results.len() != requests.len() {
        return Err(ThreatIntelError::OsvResultCountMismatch {
            queries: requests.len(),
            results: response.results.len(),
        });
    }

    let mut results = response.results;
    hydrate_osv_aliases(&mut results).await?;

    Ok(results)
}

async fn hydrate_osv_aliases(results: &mut [OsvResult]) -> Result<(), ThreatIntelError> {
    for result in results {
        for vulnerability in &mut result.vulns {
            if vulnerability.aliases.is_empty() {
                let details = fetch_osv_vulnerability(&vulnerability.id).await?;
                vulnerability.aliases = details.aliases;
                if vulnerability.modified.is_none() {
                    vulnerability.modified = details.modified;
                }
            }
        }
    }

    Ok(())
}

async fn fetch_osv_vulnerability(id: &str) -> Result<OsvVulnerability, ThreatIntelError> {
    Ok(reqwest::Client::new()
        .get(format!("{OSV_VULN_URL}/{id}"))
        .send()
        .await?
        .error_for_status()?
        .json::<OsvVulnerability>()
        .await?)
}

async fn fetch_cisa_kev() -> Result<CisaKevCatalog, ThreatIntelError> {
    Ok(reqwest::Client::new()
        .get(CISA_KEV_URL)
        .send()
        .await?
        .error_for_status()?
        .json::<CisaKevCatalog>()
        .await?)
}

fn index_cisa_kev(catalog: CisaKevCatalog) -> BTreeMap<String, CisaKevVulnerability> {
    catalog
        .vulnerabilities
        .into_iter()
        .map(|vulnerability| (vulnerability.cve_id.clone(), vulnerability))
        .collect()
}

fn apply_osv_and_kev_results(
    inventory: &mut [InventoryPackage],
    results: Vec<OsvResult>,
    kev_index: &BTreeMap<String, CisaKevVulnerability>,
) {
    for (package, result) in inventory.iter_mut().zip(results) {
        package.advisories = result
            .vulns
            .into_iter()
            .map(|vuln| {
                let cve_aliases = vuln
                    .aliases
                    .iter()
                    .filter(|alias| alias.starts_with("CVE-"))
                    .cloned()
                    .collect::<Vec<_>>();
                let kev_match =
                    cve_aliases
                        .iter()
                        .find_map(|cve| kev_index.get(cve))
                        .map(|match_| KevMatch {
                            cve_id: match_.cve_id.clone(),
                            vulnerability_name: match_.vulnerability_name.clone(),
                            date_added: match_.date_added.clone(),
                            due_date: match_.due_date.clone(),
                            known_ransomware_campaign_use: match_
                                .known_ransomware_campaign_use
                                .clone(),
                        });

                AdvisorySummary {
                    id: vuln.id,
                    modified: vuln.modified,
                    aliases: vuln.aliases,
                    cve_aliases,
                    kev_match,
                }
            })
            .collect();
        package
            .advisories
            .sort_by(|left, right| left.id.cmp(&right.id));
    }
}

fn current_unix_timestamp() -> Result<i64, ThreatIntelError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ThreatIntelError::InvalidSystemTime)?
        .as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InventoryPackage;

    #[test]
    fn cve_alias_with_kev_entry_sets_kev_match() {
        let mut inventory = vec![InventoryPackage {
            name: "demo".to_string(),
            version: "1.0.0".to_string(),
            relationships: Vec::new(),
            used_by: Vec::new(),
            advisories: Vec::new(),
        }];
        let results = vec![OsvResult {
            vulns: vec![OsvVulnerability {
                id: "GHSA-demo".to_string(),
                modified: None,
                aliases: vec!["CVE-2024-0001".to_string()],
            }],
        }];
        let kev_index = BTreeMap::from([(
            "CVE-2024-0001".to_string(),
            CisaKevVulnerability {
                cve_id: "CVE-2024-0001".to_string(),
                vulnerability_name: "Demo vulnerability".to_string(),
                date_added: "2024-01-01".to_string(),
                due_date: "2024-02-01".to_string(),
                known_ransomware_campaign_use: "Unknown".to_string(),
            },
        )]);

        apply_osv_and_kev_results(&mut inventory, results, &kev_index);

        assert_eq!(
            inventory[0].advisories[0].cve_aliases,
            vec!["CVE-2024-0001"]
        );
        assert_eq!(
            inventory[0].advisories[0]
                .kev_match
                .as_ref()
                .map(|match_| match_.cve_id.as_str()),
            Some("CVE-2024-0001")
        );
    }

    #[test]
    fn ghsa_only_advisory_has_no_kev_match() {
        let mut inventory = vec![InventoryPackage {
            name: "demo".to_string(),
            version: "1.0.0".to_string(),
            relationships: Vec::new(),
            used_by: Vec::new(),
            advisories: Vec::new(),
        }];
        let results = vec![OsvResult {
            vulns: vec![OsvVulnerability {
                id: "GHSA-demo".to_string(),
                modified: None,
                aliases: Vec::new(),
            }],
        }];

        apply_osv_and_kev_results(&mut inventory, results, &BTreeMap::new());

        assert!(inventory[0].advisories[0].cve_aliases.is_empty());
        assert!(inventory[0].advisories[0].kev_match.is_none());
    }

    #[test]
    fn sqlite_cache_returns_fresh_osv_entries() {
        let cache_path = std::env::temp_dir().join(format!(
            "sknr-cache-test-{}.db",
            current_unix_timestamp().unwrap()
        ));
        let cache = ThreatIntelCache::open(&cache_path).unwrap();
        let result = OsvResult {
            vulns: vec![OsvVulnerability {
                id: "GHSA-cache".to_string(),
                modified: None,
                aliases: Vec::new(),
            }],
        };

        cache
            .put_osv_result("demo", "1.0.0", &result, 1_000)
            .unwrap();
        let cached = cache
            .get_cached_osv_result("demo", "1.0.0", 1_000 + CACHE_TTL_SECONDS - 1)
            .unwrap()
            .unwrap();
        let expired = cache
            .get_cached_osv_result("demo", "1.0.0", 1_000 + CACHE_TTL_SECONDS + 1)
            .unwrap();

        assert_eq!(cached.vulns[0].id, "GHSA-cache");
        assert!(expired.is_none());

        drop(cache);
        let _ = fs::remove_file(cache_path);
    }
}
