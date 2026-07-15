pub mod model;
pub mod scanner;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
