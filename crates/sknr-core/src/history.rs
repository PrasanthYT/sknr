use crate::model::ScanReport;
use crate::summary::DashboardSummary;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    pub id: i64,
    pub root: String,
    pub created_at: i64,
    pub summary: DashboardSummary,
}

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("failed to initialize history directory {path}: {source}")]
    InitDirectory {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to open scan history database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("failed to serialize scan history JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("system clock is before UNIX epoch")]
    InvalidSystemTime,
}

pub fn save_scan_history(
    db_path: &Path,
    report: &ScanReport,
    summary: &DashboardSummary,
) -> Result<i64, HistoryError> {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent).map_err(|source| HistoryError::InitDirectory {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let connection = open_history(db_path)?;
    let created_at = current_unix_timestamp()?;
    connection.execute(
        "insert into scan_history (root, created_at, summary_json, scan_json) values (?1, ?2, ?3, ?4)",
        params![
            report.root,
            created_at,
            serde_json::to_string(summary)?,
            serde_json::to_string(report)?
        ],
    )?;
    Ok(connection.last_insert_rowid())
}

pub fn list_scan_history(db_path: &Path) -> Result<Vec<ScanHistoryEntry>, HistoryError> {
    let connection = open_history(db_path)?;
    let mut statement = connection.prepare(
        "select id, root, created_at, summary_json from scan_history order by created_at desc, id desc",
    )?;
    let entries = statement
        .query_map([], |row| {
            let summary_json: String = row.get(3)?;
            let summary = serde_json::from_str(&summary_json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok(ScanHistoryEntry {
                id: row.get(0)?,
                root: row.get(1)?,
                created_at: row.get(2)?,
                summary,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries)
}

pub fn load_scan_history(db_path: &Path, id: i64) -> Result<Option<ScanReport>, HistoryError> {
    let connection = open_history(db_path)?;
    let mut statement = connection.prepare("select scan_json from scan_history where id = ?1")?;
    let mut rows = statement.query(params![id])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let scan_json: String = row.get(0)?;
    Ok(Some(serde_json::from_str(&scan_json)?))
}

pub fn latest_scan_history(db_path: &Path) -> Result<Option<ScanHistoryEntry>, HistoryError> {
    Ok(list_scan_history(db_path)?.into_iter().next())
}

fn open_history(db_path: &Path) -> Result<Connection, HistoryError> {
    let connection = Connection::open(db_path)?;
    connection.execute_batch(
        "create table if not exists scan_history (
            id integer primary key autoincrement,
            root text not null,
            created_at integer not null,
            summary_json text not null,
            scan_json text not null
        );",
    )?;
    Ok(connection)
}

fn current_unix_timestamp() -> Result<i64, HistoryError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HistoryError::InvalidSystemTime)?
        .as_secs() as i64)
}
