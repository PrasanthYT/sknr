use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, ValueEnum};
use serde::Deserialize;
use sknr_core::executor::execute_codex_plan;
use sknr_core::github::{create_pull_request, GithubAuthMode, PullRequestOptions};
use sknr_core::history::{
    latest_scan_history, list_scan_history, load_scan_history, save_scan_history, ScanHistoryEntry,
};
use sknr_core::init::generate_sknr_config;
use sknr_core::model::ScanReport;
use sknr_core::priority::{prioritize_inventory_with_openai, AiPriorityOptions};
use sknr_core::remediation::{build_remediation_plans, RemediationPlan};
use sknr_core::report::{build_dashboard_data_with_history, render_static_report, DashboardData};
use sknr_core::sarif::render_sarif;
use sknr_core::sbom::render_cyclonedx_json;
use sknr_core::scanner::scan_npm_workspace;
use sknr_core::summary::DashboardSummary;
use sknr_core::threat_intel::{enrich_inventory_with_threat_intel, ThreatIntelOptions};
use sknr_core::verification::verify_scan_reduction;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

type AppError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Parser)]
#[command(name = "sknr")]
#[command(version)]
#[command(about = "Self-hosted dependency risk scanner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, clap::Subcommand)]
enum Commands {
    /// Scan an npm workspace and print dependency inventory.
    Scan {
        /// Repository or fixture root containing package.json and package-lock.json.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Skip OSV advisory lookups and emit dependency inventory only.
        #[arg(long)]
        offline: bool,
        /// Override the SQLite threat-intel cache path.
        #[arg(long)]
        cache_path: Option<PathBuf>,
        /// Force refresh of OSV and CISA KEV cache entries.
        #[arg(long)]
        refresh_cache: bool,
        /// Ask OpenAI to assign priority buckets to advisory-backed findings.
        #[arg(long)]
        ai_prioritize: bool,
        /// Override the OpenAI model used for AI priority buckets.
        #[arg(long)]
        openai_model: Option<String>,
        /// Persist the scan and summary to `.sknr/cache.db`.
        #[arg(long)]
        save_history: bool,
        /// Exit non-zero when findings meet or exceed this priority threshold.
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
    },
    /// Generate an initial sknr.config.yaml from npm workspaces.
    Init {
        /// Repository root containing package.json workspaces.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Overwrite an existing sknr.config.yaml.
        #[arg(long)]
        force: bool,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Build remediation plans for advisory-backed packages.
    Plan {
        /// Repository or fixture root containing package.json and package-lock.json.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Override the SQLite threat-intel cache path.
        #[arg(long)]
        cache_path: Option<PathBuf>,
        /// Force refresh of OSV and CISA KEV cache entries.
        #[arg(long)]
        refresh_cache: bool,
    },
    /// Generate or execute a Codex remediation task for one package/service.
    Fix {
        /// Repository or fixture root containing package.json and package-lock.json.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Package to remediate.
        #[arg(long)]
        package: String,
        /// Service that should be in scope.
        #[arg(long)]
        service: String,
        /// Actually run `codex exec`; omitted means dry-run only.
        #[arg(long)]
        execute: bool,
        /// After execution, commit, push, and open a GitHub PR.
        #[arg(long)]
        create_pr: bool,
        /// PR base branch.
        #[arg(long, default_value = "main")]
        base: String,
        /// Git remote to push.
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Fix branch name. Defaults to `sknr/fix-{service}-{package}`.
        #[arg(long)]
        branch: Option<String>,
        /// GitHub repository in `owner/repo` form.
        #[arg(long)]
        repo: Option<String>,
        /// PR title.
        #[arg(long)]
        pr_title: Option<String>,
        /// Open the PR as draft.
        #[arg(long)]
        draft: bool,
        /// GitHub auth mode for PR creation.
        #[arg(long, value_enum, default_value_t = GithubAuthOption::Auto)]
        github_auth: GithubAuthOption,
        /// Override the SQLite threat-intel cache path.
        #[arg(long)]
        cache_path: Option<PathBuf>,
        /// Force refresh of OSV and CISA KEV cache entries.
        #[arg(long)]
        refresh_cache: bool,
    },
    /// Compare a previous scan snapshot against a fresh scan.
    Verify {
        /// Repository or fixture root containing package.json and package-lock.json.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Previous `sknr scan --format json` snapshot.
        #[arg(long)]
        before: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Override the SQLite threat-intel cache path.
        #[arg(long)]
        cache_path: Option<PathBuf>,
        /// Force refresh of OSV and CISA KEV cache entries.
        #[arg(long)]
        refresh_cache: bool,
    },
    /// Serve the Next.js dashboard API and static assets when built.
    Dashboard {
        /// Repository or fixture root containing package.json and package-lock.json.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Address to bind.
        #[arg(long, default_value = "127.0.0.1:4317")]
        addr: SocketAddr,
        /// Override the SQLite threat-intel cache path.
        #[arg(long)]
        cache_path: Option<PathBuf>,
        /// Force refresh of OSV and CISA KEV cache entries.
        #[arg(long)]
        refresh_cache: bool,
    },
    /// Generate a self-contained static HTML security report.
    Report {
        /// Repository or fixture root containing package.json and package-lock.json.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output HTML path.
        #[arg(long, default_value = "security-report.html")]
        out: PathBuf,
        /// Override the SQLite threat-intel cache path.
        #[arg(long)]
        cache_path: Option<PathBuf>,
        /// Force refresh of OSV and CISA KEV cache entries.
        #[arg(long)]
        refresh_cache: bool,
    },
    /// Read saved scan history from `.sknr/cache.db`.
    History {
        #[command(subcommand)]
        command: HistoryCommands,
    },
    /// Export a CycloneDX SBOM from the npm inventory.
    Sbom {
        /// Repository or fixture root containing package.json and package-lock.json.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output SBOM path.
        #[arg(long, default_value = "bom.json")]
        out: PathBuf,
        /// SBOM format.
        #[arg(long, value_enum, default_value_t = SbomFormat::CyclonedxJson)]
        format: SbomFormat,
        /// Override the SQLite threat-intel cache path.
        #[arg(long)]
        cache_path: Option<PathBuf>,
        /// Force refresh of OSV and CISA KEV cache entries.
        #[arg(long)]
        refresh_cache: bool,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Debug, ValueEnum)]
enum FailOn {
    FixNow,
    ThisSprint,
    Monitor,
    Any,
}

#[derive(Clone, Debug, ValueEnum)]
enum SbomFormat {
    CyclonedxJson,
}

#[derive(Clone, Debug, ValueEnum)]
enum GithubAuthOption {
    Auto,
    Gh,
    Token,
}

impl From<GithubAuthOption> for GithubAuthMode {
    fn from(value: GithubAuthOption) -> Self {
        match value {
            GithubAuthOption::Auto => GithubAuthMode::Auto,
            GithubAuthOption::Gh => GithubAuthMode::Gh,
            GithubAuthOption::Token => GithubAuthMode::Token,
        }
    }
}

#[derive(Debug, clap::Subcommand)]
enum HistoryCommands {
    /// List saved scan history entries.
    List {
        /// Repository root.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Show one saved scan history entry by ID.
    Show {
        /// Repository root.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Scan history ID.
        #[arg(long)]
        id: i64,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), AppError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            offline,
            cache_path,
            refresh_cache,
            ai_prioritize,
            openai_model,
            save_history,
            fail_on,
        } => {
            let default_cache_path = path.join(".sknr").join("cache.db");
            let mut report = scan_npm_workspace(&path)?;
            if !offline {
                enrich_inventory_with_threat_intel(
                    &mut report.inventory,
                    &ThreatIntelOptions {
                        cache_path: cache_path.unwrap_or(default_cache_path.clone()),
                        refresh_cache,
                    },
                )
                .await?;
            }
            if ai_prioritize
                && report
                    .inventory
                    .iter()
                    .any(|package| !package.advisories.is_empty())
            {
                let api_key = std::env::var("OPENAI_API_KEY").map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "OPENAI_API_KEY is required when --ai-prioritize has findings",
                    )
                })?;
                prioritize_inventory_with_openai(
                    &mut report.inventory,
                    &AiPriorityOptions {
                        api_key,
                        model: openai_model
                            .or_else(|| std::env::var("SKNR_OPENAI_MODEL").ok())
                            .unwrap_or_else(|| "gpt-5.6".to_string()),
                    },
                )
                .await?;
            }

            match format {
                OutputFormat::Text => print_text_report(&report),
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                OutputFormat::Sarif => {
                    println!("{}", serde_json::to_string_pretty(&render_sarif(&report))?);
                }
            }

            if save_history {
                let plans = if offline {
                    Vec::new()
                } else {
                    build_remediation_plans(&report).await.unwrap_or_default()
                };
                let summary = sknr_core::summary::build_dashboard_summary(&report, &plans);
                let id = save_scan_history(&default_cache_path, &report, &summary)?;
                eprintln!("saved scan history entry {id}");
            }

            if let Some(threshold) = fail_on {
                if should_fail_scan(&report, threshold) {
                    std::process::exit(10);
                }
            }
        }
        Commands::Init {
            path,
            force,
            format,
        } => {
            let summary = generate_sknr_config(&path, force)?;
            match format {
                OutputFormat::Text => print_init_summary(&summary),
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&summary)?),
                OutputFormat::Sarif => {
                    return Err("init does not support --format sarif".into());
                }
            }
        }
        Commands::Plan {
            path,
            format,
            cache_path,
            refresh_cache,
        } => {
            let report = scan_with_threat_intel(&path, cache_path, refresh_cache).await?;
            let plans = build_remediation_plans(&report).await?;
            match format {
                OutputFormat::Text => print_plans(&plans),
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&plans)?),
                OutputFormat::Sarif => {
                    return Err("plan does not support --format sarif".into());
                }
            }
        }
        Commands::Fix {
            path,
            package,
            service,
            execute,
            create_pr,
            base,
            remote,
            branch,
            repo,
            pr_title,
            draft,
            github_auth,
            cache_path,
            refresh_cache,
        } => {
            let report = scan_with_threat_intel(&path, cache_path, refresh_cache).await?;
            let plans = build_remediation_plans(&report).await?;
            let plan = plans
                .iter()
                .find(|plan| {
                    plan.package == package && plan.services.iter().any(|item| item == &service)
                })
                .ok_or_else(|| {
                    format!(
                        "no remediation plan found for package `{package}` in service `{service}`"
                    )
                })?;

            print_fix_plan(plan, execute);
            if execute {
                if create_pr {
                    execute_fix_and_open_pr(
                        &path,
                        &report,
                        plan,
                        FixPrOptions {
                            base,
                            remote,
                            branch,
                            repo,
                            pr_title,
                            draft,
                            github_auth: github_auth.into(),
                        },
                    )
                    .await?;
                } else {
                    execute_codex_plan(&std::env::current_dir()?, plan)?;
                }
            }
        }
        Commands::Verify {
            path,
            before,
            format,
            cache_path,
            refresh_cache,
        } => {
            let before_raw = fs::read_to_string(&before)?;
            let before_report: ScanReport = serde_json::from_str(&before_raw)?;
            let after_report = scan_with_threat_intel(&path, cache_path, refresh_cache).await?;
            let verification = verify_scan_reduction(&before_report, &after_report);
            match format {
                OutputFormat::Text => print_verification(&verification),
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&verification)?),
                OutputFormat::Sarif => {
                    return Err("verify does not support --format sarif".into());
                }
            }
        }
        Commands::Dashboard {
            path,
            addr,
            cache_path,
            refresh_cache,
        } => {
            serve_dashboard(path, cache_path, refresh_cache, addr).await?;
        }
        Commands::Report {
            path,
            out,
            cache_path,
            refresh_cache,
        } => {
            let data = dashboard_data(&path, cache_path, refresh_cache).await?;
            let html = render_static_report(&data)?;
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(&out, html)?;
            println!("wrote {}", out.display());
        }
        Commands::History { command } => match command {
            HistoryCommands::List { path, format } => {
                let entries = list_scan_history(&default_cache_path(&path))?;
                match format {
                    OutputFormat::Text => print_history_entries(&entries),
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&entries)?),
                    OutputFormat::Sarif => {
                        return Err("history list does not support --format sarif".into());
                    }
                }
            }
            HistoryCommands::Show { path, id, format } => {
                let Some(report) = load_scan_history(&default_cache_path(&path), id)? else {
                    return Err(format!("no scan history entry found for id {id}").into());
                };
                match format {
                    OutputFormat::Text => print_text_report(&report),
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
                    OutputFormat::Sarif => {
                        println!("{}", serde_json::to_string_pretty(&render_sarif(&report))?);
                    }
                }
            }
        },
        Commands::Sbom {
            path,
            out,
            format,
            cache_path,
            refresh_cache,
        } => {
            let report = scan_with_threat_intel(&path, cache_path, refresh_cache).await?;
            let contents = match format {
                SbomFormat::CyclonedxJson => {
                    serde_json::to_string_pretty(&render_cyclonedx_json(&report))?
                }
            };
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(&out, contents)?;
            println!("wrote {}", out.display());
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct DashboardState {
    path: PathBuf,
    cache_path: Option<PathBuf>,
    refresh_cache: bool,
}

#[derive(Debug)]
struct FixPrOptions {
    base: String,
    remote: String,
    branch: Option<String>,
    repo: Option<String>,
    pr_title: Option<String>,
    draft: bool,
    github_auth: GithubAuthMode,
}

fn default_cache_path(path: &std::path::Path) -> PathBuf {
    path.join(".sknr").join("cache.db")
}

fn should_fail_scan(report: &ScanReport, threshold: FailOn) -> bool {
    report.inventory.iter().any(|package| {
        if package.advisories.is_empty() {
            return false;
        }

        match threshold {
            FailOn::Any => true,
            FailOn::FixNow => matches!(
                package.priority.as_ref().map(|priority| priority.bucket),
                Some(sknr_core::model::PriorityBucket::FixNow)
            ),
            FailOn::ThisSprint => matches!(
                package.priority.as_ref().map(|priority| priority.bucket),
                Some(sknr_core::model::PriorityBucket::FixNow)
                    | Some(sknr_core::model::PriorityBucket::ThisSprint)
            ),
            FailOn::Monitor => true,
        }
    })
}

async fn execute_fix_and_open_pr(
    path: &PathBuf,
    before_report: &ScanReport,
    plan: &RemediationPlan,
    options: FixPrOptions,
) -> Result<(), AppError> {
    let repo_root = std::env::current_dir()?;
    ensure_git_clean(&repo_root)?;
    let branch = options
        .branch
        .unwrap_or_else(|| default_fix_branch(&plan.services, &plan.package));

    save_before_snapshot(path, before_report)?;
    run_git(&repo_root, &["switch", "-c", &branch])?;
    execute_codex_plan(&repo_root, plan)?;

    let after_report = scan_with_threat_intel(path, None, false).await?;
    let verification = verify_scan_reduction(before_report, &after_report);
    print_verification(&verification);

    run_git(&repo_root, &["add", "-A"])?;
    run_git(
        &repo_root,
        &[
            "commit",
            "-m",
            &format!("fix: update {} remediation", plan.package),
        ],
    )?;
    run_git(&repo_root, &["push", "-u", &options.remote, &branch])?;

    let repo = match options.repo {
        Some(repo) => repo,
        None => infer_github_repo(&repo_root, &options.remote)?,
    };
    let title = options
        .pr_title
        .unwrap_or_else(|| format!("fix: update {}", plan.package));
    let body = format!(
        "## Summary\n- update `{}` from `{}` to `{}`\n- affected services: {}\n\n## Verification\n- risk reduced: {}\n- vulnerable packages: {} -> {}\n- advisories: {} -> {}\n",
        plan.package,
        plan.current_version,
        plan.target_version,
        plan.services.join(", "),
        verification.risk_reduced,
        verification.before_vulnerable_packages,
        verification.after_vulnerable_packages,
        verification.before_advisories,
        verification.after_advisories
    );
    let result = create_pull_request(&PullRequestOptions {
        repo,
        head: branch,
        base: options.base,
        title,
        body,
        draft: options.draft,
        auth_mode: options.github_auth,
    })
    .await?;
    println!("opened PR {}", result.url);

    Ok(())
}

fn ensure_git_clean(repo_root: &std::path::Path) -> Result<(), AppError> {
    let output = Command::new("git")
        .arg("status")
        .arg("--porcelain")
        .current_dir(repo_root)
        .output()?;
    if !output.status.success() {
        return Err("failed to inspect git status".into());
    }
    if !output.stdout.is_empty() {
        return Err("working tree must be clean before --create-pr".into());
    }
    Ok(())
}

fn run_git(repo_root: &std::path::Path, args: &[&str]) -> Result<(), AppError> {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("git {} failed with {status}", args.join(" ")).into())
    }
}

fn infer_github_repo(repo_root: &std::path::Path, remote: &str) -> Result<String, AppError> {
    let output = Command::new("git")
        .arg("remote")
        .arg("get-url")
        .arg(remote)
        .current_dir(repo_root)
        .output()?;
    if !output.status.success() {
        return Err(format!("failed to read git remote `{remote}`").into());
    }
    let url = String::from_utf8_lossy(&output.stdout);
    normalize_github_remote(url.trim())
        .ok_or_else(|| format!("could not infer owner/repo from remote `{}`", url.trim()).into())
}

fn normalize_github_remote(url: &str) -> Option<String> {
    let without_suffix = url.strip_suffix(".git").unwrap_or(url);
    if let Some(path) = without_suffix.strip_prefix("https://github.com/") {
        return Some(path.to_string());
    }
    let marker = ':';
    if without_suffix.starts_with("git@") {
        return without_suffix
            .split_once(marker)
            .map(|(_, path)| path.to_string());
    }
    None
}

fn save_before_snapshot(path: &std::path::Path, report: &ScanReport) -> Result<PathBuf, AppError> {
    let snapshots = path.join(".sknr").join("snapshots");
    fs::create_dir_all(&snapshots)?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let snapshot = snapshots.join(format!("before-{timestamp}.json"));
    fs::write(&snapshot, serde_json::to_string_pretty(report)?)?;
    println!("saved before snapshot {}", snapshot.display());
    Ok(snapshot)
}

fn default_fix_branch(services: &[String], package: &str) -> String {
    let service = services.first().map(String::as_str).unwrap_or("workspace");
    format!(
        "sknr/fix-{}-{}",
        sanitize_branch_part(service),
        sanitize_branch_part(package)
    )
}

fn sanitize_branch_part(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[derive(Debug, Deserialize)]
struct FixDryRunRequest {
    package: String,
    service: String,
}

#[derive(Debug, Deserialize)]
struct HistoryScanQuery {
    id: i64,
}

async fn serve_dashboard(
    path: PathBuf,
    cache_path: Option<PathBuf>,
    refresh_cache: bool,
    addr: SocketAddr,
) -> Result<(), AppError> {
    let state = Arc::new(DashboardState {
        path,
        cache_path,
        refresh_cache,
    });

    let app = Router::new()
        .route("/", get(dashboard_root))
        .route("/api/dashboard", get(api_dashboard))
        .route("/api/scan", get(api_scan))
        .route("/api/history", get(api_history))
        .route("/api/history/scan", get(api_history_scan))
        .route("/api/plans", get(api_plans))
        .route("/api/summary", get(api_summary))
        .route("/api/fix/dry-run", post(api_fix_dry_run))
        .layer(CorsLayer::permissive())
        .with_state(state);
    let static_dir = std::env::current_dir()?
        .join("web")
        .join("dashboard")
        .join("out");
    let app = if static_dir.exists() {
        app.fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true))
    } else {
        app
    };

    println!("Sknr dashboard API listening on http://{addr}");
    println!("Next.js dashboard can use NEXT_PUBLIC_SKNR_API_BASE=http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn dashboard_root() -> &'static str {
    "Sknr dashboard API is running. Use /api/dashboard, /api/summary, /api/scan, /api/plans, or run the Next.js app in web/dashboard/."
}

async fn api_dashboard(
    State(state): State<Arc<DashboardState>>,
) -> Result<Json<DashboardData>, (axum::http::StatusCode, String)> {
    let state = (*state).clone();
    run_dashboard_blocking(move || {
        block_on_dashboard(async move {
            dashboard_data(&state.path, state.cache_path, state.refresh_cache).await
        })
    })
    .await
    .map(Json)
}

async fn api_scan(
    State(state): State<Arc<DashboardState>>,
) -> Result<Json<ScanReport>, (axum::http::StatusCode, String)> {
    let state = (*state).clone();
    run_dashboard_blocking(move || {
        block_on_dashboard(async move {
            scan_with_threat_intel(&state.path, state.cache_path, state.refresh_cache).await
        })
    })
    .await
    .map(Json)
}

async fn api_history(
    State(state): State<Arc<DashboardState>>,
) -> Result<Json<Vec<ScanHistoryEntry>>, (axum::http::StatusCode, String)> {
    let state = (*state).clone();
    run_dashboard_blocking(move || {
        list_scan_history(&default_cache_path(&state.path)).map_err(|error| error.to_string())
    })
    .await
    .map(Json)
}

async fn api_history_scan(
    State(state): State<Arc<DashboardState>>,
    Query(query): Query<HistoryScanQuery>,
) -> Result<Json<ScanReport>, (axum::http::StatusCode, String)> {
    let state = (*state).clone();
    run_dashboard_blocking(move || {
        load_scan_history(&default_cache_path(&state.path), query.id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("no scan history entry found for id {}", query.id))
    })
    .await
    .map(Json)
}

async fn api_plans(
    State(state): State<Arc<DashboardState>>,
) -> Result<Json<Vec<RemediationPlan>>, (axum::http::StatusCode, String)> {
    let state = (*state).clone();
    run_dashboard_blocking(move || {
        block_on_dashboard(async move {
            let report =
                scan_with_threat_intel(&state.path, state.cache_path, state.refresh_cache).await?;
            let plans = build_remediation_plans(&report).await?;
            Ok::<_, AppError>(plans)
        })
    })
    .await
    .map(Json)
}

async fn api_summary(
    State(state): State<Arc<DashboardState>>,
) -> Result<Json<DashboardSummary>, (axum::http::StatusCode, String)> {
    let state = (*state).clone();
    run_dashboard_blocking(move || {
        block_on_dashboard(async move {
            let data = dashboard_data(&state.path, state.cache_path, state.refresh_cache).await?;
            Ok::<_, AppError>(data.summary)
        })
    })
    .await
    .map(Json)
}

async fn api_fix_dry_run(
    State(state): State<Arc<DashboardState>>,
    Json(request): Json<FixDryRunRequest>,
) -> Result<Json<RemediationPlan>, (axum::http::StatusCode, String)> {
    let state = (*state).clone();
    run_dashboard_blocking(move || {
        block_on_dashboard(async move {
            let report =
                scan_with_threat_intel(&state.path, state.cache_path, state.refresh_cache).await?;
            let plans = build_remediation_plans(&report).await?;
            let plan = plans
                .into_iter()
                .find(|plan| {
                    plan.package == request.package
                        && plan
                            .services
                            .iter()
                            .any(|service| service == &request.service)
                })
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "no remediation plan found")
                })?;
            Ok::<_, AppError>(plan)
        })
    })
    .await
    .map(Json)
}

async fn run_dashboard_blocking<T, F>(work: F) -> Result<T, (axum::http::StatusCode, String)>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                error.to_string(),
            )
        })?
        .map_err(|error| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, error))
}

fn block_on_dashboard<T, F>(future: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, AppError>>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(future)
        .map_err(|error| error.to_string())
}

async fn dashboard_data(
    path: &PathBuf,
    cache_path: Option<PathBuf>,
    refresh_cache: bool,
) -> Result<DashboardData, AppError> {
    let report = scan_with_threat_intel(path, cache_path, refresh_cache).await?;
    let plans = build_remediation_plans(&report).await?;
    let latest_history = latest_scan_history(&default_cache_path(path))
        .ok()
        .flatten();
    Ok(build_dashboard_data_with_history(
        report,
        plans,
        latest_history,
    ))
}

async fn scan_with_threat_intel(
    path: &PathBuf,
    cache_path: Option<PathBuf>,
    refresh_cache: bool,
) -> Result<ScanReport, AppError> {
    let default_cache_path = path.join(".sknr").join("cache.db");
    let mut report = scan_npm_workspace(path)?;
    enrich_inventory_with_threat_intel(
        &mut report.inventory,
        &ThreatIntelOptions {
            cache_path: cache_path.unwrap_or(default_cache_path),
            refresh_cache,
        },
    )
    .await?;
    Ok(report)
}

fn print_text_report(report: &sknr_core::model::ScanReport) {
    println!("root: {}", report.root);
    println!("packages: {}", report.inventory.len());
    println!(
        "vulnerable packages: {}",
        report
            .inventory
            .iter()
            .filter(|package| !package.advisories.is_empty())
            .count()
    );
    println!(
        "KEV matches: {}",
        report
            .inventory
            .iter()
            .flat_map(|package| package.advisories.iter())
            .filter(|advisory| advisory.kev_match.is_some())
            .count()
    );
    println!(
        "reachable packages: {}",
        report
            .inventory
            .iter()
            .filter(|package| {
                package
                    .used_by
                    .iter()
                    .any(|usage| usage.reachability.imported)
            })
            .count()
    );
    println!(
        "prioritized packages: {}",
        report
            .inventory
            .iter()
            .filter(|package| package.priority.is_some())
            .count()
    );
    println!("services: {}", report.services.len());
    println!("topology nodes: {}", report.topology.nodes.len());
    println!("topology edges: {}", report.topology.edges.len());

    for service in &report.services {
        println!();
        println!(
            "{} ({})",
            service.name,
            if service.dependencies.is_empty() {
                "0 dependencies".to_string()
            } else {
                format!("{} dependencies", service.dependencies.len())
            }
        );
        println!("  package: {}", service.package_name);
        println!("  path: {}", service.path);
        println!("  internet facing: {}", service.internet_facing);

        for dependency in &service.dependencies {
            println!(
                "  - {}@{} ({:?})",
                dependency.name, dependency.version, dependency.relationship
            );
        }
    }

    println!();
    println!("inventory:");
    for package in &report.inventory {
        println!(
            "  - {}@{} (used by {} services, {} advisories, reachable: {}, priority: {})",
            package.name,
            package.version,
            package.used_by.len(),
            package.advisories.len(),
            package
                .used_by
                .iter()
                .any(|usage| usage.reachability.imported),
            package
                .priority
                .as_ref()
                .map(|priority| format!("{:?}", priority.bucket))
                .unwrap_or_else(|| "none".to_string())
        );
    }
}

fn print_init_summary(summary: &sknr_core::init::InitSummary) {
    println!("wrote {}", summary.path);
    println!("overwritten: {}", summary.overwritten);
    println!("services: {}", summary.services.len());
    for service in &summary.services {
        println!(
            "  - {} ({}, internet facing: {})",
            service.name, service.path, service.internet_facing
        );
    }
}

fn print_history_entries(entries: &[sknr_core::history::ScanHistoryEntry]) {
    println!("scan history entries: {}", entries.len());
    for entry in entries {
        println!(
            "  - #{} root={} created_at={} packages={} vulnerable={} advisories={}",
            entry.id,
            entry.root,
            entry.created_at,
            entry.summary.packages,
            entry.summary.vulnerable_packages,
            entry.summary.advisories
        );
    }
}

fn print_plans(plans: &[RemediationPlan]) {
    println!("remediation plans: {}", plans.len());
    for plan in plans {
        println!();
        println!(
            "{}: {} -> {} ({:?})",
            plan.package, plan.current_version, plan.target_version, plan.upgrade_risk
        );
        println!("  services: {}", plan.services.join(", "));
        println!("  priority: {:?}", plan.priority_bucket);
        for reason in &plan.reasons {
            println!("  - {reason}");
        }
    }
}

fn print_fix_plan(plan: &RemediationPlan, execute: bool) {
    println!(
        "{}: {} -> {} ({:?})",
        plan.package, plan.current_version, plan.target_version, plan.upgrade_risk
    );
    println!("services: {}", plan.services.join(", "));
    println!("execute: {execute}");
    println!();
    println!("Codex task:");
    println!("{}", plan.codex_task);
}

fn print_verification(report: &sknr_core::verification::VerificationReport) {
    println!("risk reduced: {}", report.risk_reduced);
    println!(
        "vulnerable packages: {} -> {}",
        report.before_vulnerable_packages, report.after_vulnerable_packages
    );
    println!(
        "advisories: {} -> {}",
        report.before_advisories, report.after_advisories
    );
    println!("fixed packages: {}", report.fixed_packages.len());
    for package in &report.fixed_packages {
        println!(
            "  - {}: {} -> {} (advisories {} -> {})",
            package.package,
            package.before_version,
            package
                .after_version
                .clone()
                .unwrap_or_else(|| "not present".to_string()),
            package.before_advisories,
            package.after_advisories
        );
    }
}
