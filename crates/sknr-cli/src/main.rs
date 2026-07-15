use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, ValueEnum};
use serde::Deserialize;
use sknr_core::executor::execute_codex_plan;
use sknr_core::model::ScanReport;
use sknr_core::priority::{prioritize_inventory_with_openai, AiPriorityOptions};
use sknr_core::remediation::{build_remediation_plans, RemediationPlan};
use sknr_core::report::{build_dashboard_data, render_static_report, DashboardData};
use sknr_core::scanner::scan_npm_workspace;
use sknr_core::summary::DashboardSummary;
use sknr_core::threat_intel::{enrich_inventory_with_threat_intel, ThreatIntelOptions};
use sknr_core::verification::verify_scan_reduction;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
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
    },
    /// Build remediation plans for advisory-backed packages.
    Plan {
        /// Repository or fixture root containing package.json and package-lock.json.
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
}

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
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
        } => {
            let default_cache_path = path.join(".sknr").join("cache.db");
            let mut report = scan_npm_workspace(&path)?;
            if !offline {
                enrich_inventory_with_threat_intel(
                    &mut report.inventory,
                    &ThreatIntelOptions {
                        cache_path: cache_path.unwrap_or(default_cache_path),
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
            }
        }
        Commands::Fix {
            path,
            package,
            service,
            execute,
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
                execute_codex_plan(&std::env::current_dir()?, plan)?;
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
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct DashboardState {
    path: PathBuf,
    cache_path: Option<PathBuf>,
    refresh_cache: bool,
}

#[derive(Debug, Deserialize)]
struct FixDryRunRequest {
    package: String,
    service: String,
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
    Ok(build_dashboard_data(report, plans))
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
