use crate::remediation::RemediationPlan;
use std::path::Path;
use std::process::{Command, Stdio};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("failed to start Codex: {0}")]
    Start(std::io::Error),
    #[error("Codex executor failed with status {0}")]
    Failed(String),
}

pub fn execute_codex_plan(root: &Path, plan: &RemediationPlan) -> Result<(), ExecutorError> {
    let status = Command::new("codex")
        .arg("exec")
        .arg("-C")
        .arg(root)
        .arg(&plan.codex_task)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(ExecutorError::Start)?;

    if status.success() {
        Ok(())
    } else {
        Err(ExecutorError::Failed(status.to_string()))
    }
}
