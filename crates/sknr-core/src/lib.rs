pub mod model;
pub mod osv;
pub mod reachability;
pub mod scanner;
pub mod threat_intel;
pub mod topology;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
