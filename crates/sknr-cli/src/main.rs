use clap::{Parser, ValueEnum};
use sknr_core::executor::execute_codex_plan;
use sknr_core::model::ScanReport;
use sknr_core::priority::{prioritize_inventory_with_openai, AiPriorityOptions};
use sknr_core::remediation::{build_remediation_plans, RemediationPlan};
use sknr_core::scanner::scan_npm_workspace;
use sknr_core::threat_intel::{enrich_inventory_with_threat_intel, ThreatIntelOptions};
use sknr_core::verification::verify_scan_reduction;
use std::fs;
use std::path::PathBuf;

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

async fn run() -> Result<(), Box<dyn std::error::Error>> {
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
                let api_key = std::env::var("OPENAI_API_KEY")
                    .map_err(|_| "OPENAI_API_KEY is required when --ai-prioritize has findings")?;
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
    }

    Ok(())
}

async fn scan_with_threat_intel(
    path: &PathBuf,
    cache_path: Option<PathBuf>,
    refresh_cache: bool,
) -> Result<ScanReport, Box<dyn std::error::Error>> {
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
