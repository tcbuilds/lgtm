mod config;
mod result;
mod runner;

pub use config::{StructuredCommand, load};
pub use result::config_unverified;
pub use result::{CommandEvidence, RunResults};
pub use runner::{run, run_structured};

#[cfg(test)]
mod tests;
