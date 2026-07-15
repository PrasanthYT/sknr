use clap::{Parser, ValueEnum};
use sknr_core::osv::enrich_inventory_with_osv;
use sknr_core::scanner::scan_npm_workspace;
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
        } => {
            let mut report = scan_npm_workspace(path)?;
            if !offline {
                enrich_inventory_with_osv(&mut report.inventory).await?;
            }

            match format {
                OutputFormat::Text => print_text_report(&report),
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
            }
        }
    }

    Ok(())
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
    println!("services: {}", report.services.len());

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
            "  - {}@{} (used by {} services, {} advisories)",
            package.name,
            package.version,
            package.used_by.len(),
            package.advisories.len()
        );
    }
}
