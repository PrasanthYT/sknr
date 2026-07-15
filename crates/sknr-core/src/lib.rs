pub mod model;
pub mod osv;
pub mod scanner;
pub mod topology;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
