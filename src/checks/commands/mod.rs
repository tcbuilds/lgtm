mod config;
mod result;
mod runner;

pub use config::load;
pub use result::config_unverified;
pub use result::{CommandEvidence, RunResults};
pub use runner::run;

#[cfg(test)]
mod tests;
