use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GithubAuthMode {
    Auto,
    Gh,
    Token,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequestOptions {
    pub repo: String,
    pub head: String,
    pub base: String,
    pub title: String,
    pub body: String,
    pub draft: bool,
    pub auth_mode: GithubAuthMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRequestResult {
    pub url: String,
}

#[derive(Debug, Error)]
pub enum GithubError {
    #[error("failed to start gh CLI: {0}")]
    GhStart(std::io::Error),
    #[error("gh CLI failed: {0}")]
    GhFailed(String),
    #[error("GitHub token is required; set GITHUB_TOKEN or SKNR_GITHUB_TOKEN")]
    MissingToken,
    #[error("GitHub API request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("GitHub API returned {status}: {body}")]
    Api { status: StatusCode, body: String },
    #[error("GitHub API response did not contain html_url")]
    MissingUrl,
}

pub async fn create_pull_request(
    options: &PullRequestOptions,
) -> Result<PullRequestResult, GithubError> {
    match options.auth_mode {
        GithubAuthMode::Gh => create_with_gh(options),
        GithubAuthMode::Token => create_with_token(options).await,
        GithubAuthMode::Auto => match create_with_gh(options) {
            Ok(result) => Ok(result),
            Err(_) => create_with_token(options).await,
        },
    }
}

fn create_with_gh(options: &PullRequestOptions) -> Result<PullRequestResult, GithubError> {
    let mut command = Command::new("gh");
    command
        .arg("pr")
        .arg("create")
        .arg("--repo")
        .arg(&options.repo)
        .arg("--base")
        .arg(&options.base)
        .arg("--head")
        .arg(&options.head)
        .arg("--title")
        .arg(&options.title)
        .arg("--body")
        .arg(&options.body);
    if options.draft {
        command.arg("--draft");
    }

    let output = command.output().map_err(GithubError::GhStart)?;
    if output.status.success() {
        Ok(PullRequestResult {
            url: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        })
    } else {
        Err(GithubError::GhFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

async fn create_with_token(options: &PullRequestOptions) -> Result<PullRequestResult, GithubError> {
    let token = std::env::var("SKNR_GITHUB_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .map_err(|_| GithubError::MissingToken)?;
    let url = format!("https://api.github.com/repos/{}/pulls", options.repo);
    let response = reqwest::Client::new()
        .post(url)
        .bearer_auth(token)
        .header("user-agent", "sknr")
        .json(&serde_json::json!({
            "title": options.title,
            "head": options.head,
            "base": options.base,
            "body": options.body,
            "draft": options.draft
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(GithubError::Api { status, body });
    }

    let body: serde_json::Value = response.json().await?;
    let url = body
        .get("html_url")
        .and_then(|value| value.as_str())
        .ok_or(GithubError::MissingUrl)?
        .to_string();
    Ok(PullRequestResult { url })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_can_be_constructed() {
        let options = PullRequestOptions {
            repo: "owner/repo".to_string(),
            head: "sknr/fix-demo".to_string(),
            base: "main".to_string(),
            title: "fix: update lodash".to_string(),
            body: "body".to_string(),
            draft: true,
            auth_mode: GithubAuthMode::Auto,
        };

        assert_eq!(options.repo, "owner/repo");
    }
}
