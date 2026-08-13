mod config;
mod result;
mod runner;

pub use config::{
    ConfigSnapshot, CoverageCommand, Settings, StructuredCommand, load, load_snapshot,
};
pub use result::CoverageEvidence;
pub use result::{CommandEvidence, RunResults};
pub use result::{
    budget_unverified, config_mutation_unverified, config_unverified, coverage_failure,
    is_required_command_result,
};
pub(crate) use result::{coverage_results, invalid_workspace};
pub use runner::{
    ExecutionBudget, STOP_COMMAND_BUDGET, STOP_COMMAND_BUDGET_SECONDS, run, run_coverage,
    run_coverage_with_budget, run_structured, run_structured_with_budget,
};

#[cfg(test)]
mod tests;
