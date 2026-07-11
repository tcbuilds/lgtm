use serde::Serialize;

use crate::checks::{EnforcementResult, ResultEvidence, Status};
use crate::policy::Severity;

const RULE_ID: &str = "required-repository-commands";

#[derive(Debug, Clone, Serialize)]
pub struct CommandEvidence {
    pub command: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
}

pub struct RunResults {
    pub results: Vec<EnforcementResult>,
    pub evidence: Vec<CommandEvidence>,
}

pub(super) fn result(command: &str, status: Status, reason: &str) -> EnforcementResult {
    EnforcementResult {
        rule_id: RULE_ID.to_string(),
        status,
        severity: Severity::Error,
        message: format!(
            "Required repository command `{}` {reason}.",
            sanitize(command)
        ),
        locations: Vec::new(),
        remediation: (status != Status::Passed)
            .then(|| "Fix the command or repository failure, then retry Stop.".to_string()),
        evidence: ResultEvidence {
            check: "command.required".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

pub fn config_unverified(reason: &str) -> EnforcementResult {
    result(
        "configuration",
        Status::Unverified,
        &format!("could not run ({reason})"),
    )
}

pub(super) fn not_applicable() -> EnforcementResult {
    result(
        "configuration",
        Status::NotApplicable,
        "has no configured commands",
    )
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}
