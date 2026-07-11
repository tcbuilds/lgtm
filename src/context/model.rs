use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Deterministic observables used by policy selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskContext {
    pub languages: Vec<String>,
    pub domains: Vec<String>,
    pub files_touched: Vec<String>,
    pub risk_signals: Vec<String>,
    pub repository_commands: BTreeMap<String, Vec<String>>,
}
