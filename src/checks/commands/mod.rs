mod config;
mod result;
mod runner;

pub use config::{CoverageCommand, StructuredCommand, load};
pub use result::CoverageEvidence;
pub use result::config_unverified;
pub use result::{CommandEvidence, RunResults};
pub(crate) use result::{coverage_results, invalid_workspace};
pub use runner::{run, run_coverage, run_structured};

#[cfg(test)]
mod tests;
