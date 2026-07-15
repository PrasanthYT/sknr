pub mod executor;
pub mod model;
pub mod osv;
pub mod priority;
pub mod reachability;
pub mod remediation;
pub mod report;
pub mod scanner;
pub mod summary;
pub mod threat_intel;
pub mod topology;
pub mod verification;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
