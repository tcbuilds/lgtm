//! Check backends and the enforcement-result type they all produce.
//!
//! Every check — a wrapped tool (gitleaks, ruff, semgrep), a native diff check,
//! or a command runner — normalizes its outcome to an [`EnforcementResult`].
//! That type is the lingua franca of the enforcement runtime: the PostToolUse
//! hook renders failed results back to the agent, and the future Stop gate reads
//! the persisted results to decide whether to block. Its shape mirrors
//! idea.md §Enforcement Result exactly so the JSON on the wire is stable across
//! every producer and consumer.

pub mod gitleaks;

use serde::{Deserialize, Serialize};

/// The outcome of evaluating one rule against one change.
///
/// idea.md distinguishes failure from lack of verification: `failed` means the
/// check ran and found a violation, while `unverified` means the check could not
/// run (for example a wrapped tool is absent). A missing tool must never be
/// reported as `passed`, so callers that cannot run a check emit `unverified`
/// rather than assuming compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The check ran and the rule is satisfied.
    Passed,
    /// The check ran and found a violation.
    Failed,
    /// The check ran and found a non-blocking concern.
    Warning,
    /// The check was deliberately not run for this change.
    Skipped,
    /// The rule does not apply to this change.
    NotApplicable,
    /// The check could not run (for example a wrapped tool is absent), so
    /// compliance is unknown. Never a silent pass.
    Unverified,
    /// A MUST violation was downgraded by an explicit repo-local override.
    Overridden,
}

/// A source location a result points at.
///
/// `line` is optional because not every check can localize to a line (a
/// whole-file or repository-level finding has none); when present it is
/// one-based to match the tools whose output it normalizes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Location {
    /// The file the finding is in.
    pub file: String,
    /// The one-based line, when the check can localize to one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
}

/// Provenance for a result: which check produced it and the tool version.
///
/// Recording the tool version makes an evidence record reproducible — a result
/// can be tied to the exact tool that produced it. `tool_version` is optional
/// because native checks have no external tool to version.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ResultEvidence {
    /// The check identifier, e.g. `gitleaks.detect`.
    pub check: String,
    /// The version string of the wrapped tool, when one was run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    /// Repo-configurable, tool-sourced finding descriptions, sanitized and kept
    /// out of the agent-facing `message`. A custom `.gitleaks.toml` can set an
    /// arbitrary `description` per rule, so echoing it into agent-facing text is a
    /// prompt-injection and secret-echo vector; the descriptions are retained here
    /// (evidence only, control-characters stripped) for operator triage without
    /// ever reaching the agent's stdout.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_descriptions: Vec<String>,
}

/// The normalized outcome of one check against one rule.
///
/// This is the structured enforcement-result JSON of idea.md §Enforcement
/// Result. Every field maps to a spec field; the type is `Serialize` +
/// `Deserialize` so it round-trips through the evidence JSONL unchanged and can
/// be consumed by the Stop gate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EnforcementResult {
    /// The stable registry rule ID this result is about, e.g.
    /// `no-committed-secrets`.
    pub rule_id: String,
    /// Whether the check passed, failed, or could not be verified.
    pub status: Status,
    /// The severity carried from the rule, used by the Stop gate to decide
    /// whether a failure blocks.
    pub severity: crate::policy::Severity,
    /// A human-readable, agent-facing message. For a secret finding it names the
    /// rule and the secret description but never echoes the secret value.
    pub message: String,
    /// Where the finding is, when the check can localize it.
    #[serde(default)]
    pub locations: Vec<Location>,
    /// How to fix the violation, phrased for the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Provenance: the check and tool version behind this result.
    pub evidence: ResultEvidence,
}

impl EnforcementResult {
    /// True when this result records a violation the Stop gate should act on.
    ///
    /// Only [`Status::Failed`] is a violation; `unverified`, `warning`, and the
    /// rest are surfaced but do not themselves constitute a caught violation.
    pub fn is_failure(&self) -> bool {
        self.status == Status::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_status_round_trips_through_json() {
        let statuses = [
            Status::Passed,
            Status::Failed,
            Status::Warning,
            Status::Skipped,
            Status::NotApplicable,
            Status::Unverified,
            Status::Overridden,
        ];
        for status in statuses {
            let encoded = serde_json::to_string(&status).expect("status serializes");
            let decoded: Status = serde_json::from_str(&encoded).expect("status deserializes");
            assert_eq!(decoded, status);
        }
    }
}
