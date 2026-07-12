//! Canonical rule model, embedded registry, and schema validation.
//!
//! The policy registry is the operational source of truth: an agent-neutral
//! set of engineering rules compiled into the binary at build time. This module
//! owns the typed rule model, loads the embedded registry, and validates it
//! against the JSON Schema that defines the canonical rule shape.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod config_version;
pub mod coverage;
pub mod docs;
pub mod export;
pub mod overrides;
pub mod profile;
pub mod waivers;

/// The rule schema, embedded at build time.
pub const RULE_SCHEMA_JSON: &str = include_str!("../../policy/rule.schema.json");

/// The canonical rule registry, embedded at build time.
pub const RULES_JSON: &str = include_str!("../../policy/rules.json");
pub const POLICY_BUNDLE_VERSION: &str = "V2";

pub fn bundle_digest() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(RULES_JSON.as_bytes());
    hasher.update(RULE_SCHEMA_JSON.as_bytes());
    hasher.update(coverage::COVERAGE_JSON.as_bytes());
    hasher.update(coverage::COVERAGE_SCHEMA_JSON.as_bytes());
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    format!("{:x}", hasher.finalize())
}

/// How a rule violation is reported by the enforcement runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        };
        f.write_str(text)
    }
}

/// Enforcement strength of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Must,
    Should,
    Review,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Level::Must => "must",
            Level::Should => "should",
            Level::Review => "review",
        };
        f.write_str(text)
    }
}

/// How a rule is verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    Instruction,
    Static,
    Command,
    Diff,
    Evidence,
    Hybrid,
}

/// Declared capability of a rule. This is intentionally separate from the
/// injected instruction so a rule cannot imply automation it does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mechanism {
    Native,
    Wrapped,
    Command,
    Instruction,
    Review,
    Evidence,
    Unsupported,
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Native => "native",
            Self::Wrapped => "wrapped",
            Self::Command => "command",
            Self::Instruction => "instruction",
            Self::Review => "review",
            Self::Evidence => "evidence",
            Self::Unsupported => "unsupported",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStage {
    SessionStart,
    Prompt,
    PreTool,
    PostTool,
    Stop,
    Report,
    None,
}

impl fmt::Display for EnforcementStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SessionStart => "session_start",
            Self::Prompt => "prompt",
            Self::PreTool => "pre_tool",
            Self::PostTool => "post_tool",
            Self::Stop => "stop",
            Self::Report => "report",
            Self::None => "none",
        })
    }
}

impl fmt::Display for EnforcementMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            EnforcementMode::Instruction => "instruction",
            EnforcementMode::Static => "static",
            EnforcementMode::Command => "command",
            EnforcementMode::Diff => "diff",
            EnforcementMode::Evidence => "evidence",
            EnforcementMode::Hybrid => "hybrid",
        };
        f.write_str(text)
    }
}

/// Rule category, derived from the coding-standards taxonomy.
///
/// The schema's `category` enum is the source of truth for this value list;
/// these variants mirror it exactly so illegal categories cannot deserialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Correctness,
    Security,
    Reliability,
    ErrorHandling,
    Validation,
    Architecture,
    Dependencies,
    Testing,
    Observability,
    Performance,
    Documentation,
    Refactoring,
    ChangeManagement,
    AiAgentBehavior,
    LanguageSpecific,
    Infrastructure,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Category::Correctness => "correctness",
            Category::Security => "security",
            Category::Reliability => "reliability",
            Category::ErrorHandling => "error-handling",
            Category::Validation => "validation",
            Category::Architecture => "architecture",
            Category::Dependencies => "dependencies",
            Category::Testing => "testing",
            Category::Observability => "observability",
            Category::Performance => "performance",
            Category::Documentation => "documentation",
            Category::Refactoring => "refactoring",
            Category::ChangeManagement => "change-management",
            Category::AiAgentBehavior => "ai-agent-behavior",
            Category::LanguageSpecific => "language-specific",
            Category::Infrastructure => "infrastructure",
        };
        f.write_str(text)
    }
}

/// The kind of change that switches a rule on for a task.
///
/// The schema's `activation.change_types` enum is the source of truth for this
/// value list; these variants mirror it exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeType {
    Create,
    Modify,
    Delete,
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            ChangeType::Create => "create",
            ChangeType::Modify => "modify",
            ChangeType::Delete => "delete",
        };
        f.write_str(text)
    }
}

/// Scope filter for a rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppliesTo {
    /// Languages the rule can apply to. Empty means unconstrained (matches all
    /// languages); a non-empty list restricts the rule to those languages. M2
    /// selection logic must honor this empty-means-all contract.
    pub languages: Vec<String>,
    /// Domains the rule can apply to. Empty means unconstrained (matches all
    /// domains); a non-empty list restricts the rule to those domains. M2
    /// selection logic must honor this empty-means-all contract.
    pub domains: Vec<String>,
    /// File glob patterns the rule can apply to. Empty means unconstrained
    /// (matches all files); a non-empty list restricts the rule to files
    /// matching those patterns. M2 selection logic must honor this
    /// empty-means-all contract.
    pub file_patterns: Vec<String>,
}

/// Deterministic activation signals for a rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    /// Change kinds that switch the rule on. Empty means unconstrained (any
    /// change kind activates); a non-empty list restricts activation to those
    /// change kinds. M2 selection logic must honor this empty-means-all
    /// contract.
    pub change_types: Vec<ChangeType>,
    /// Deterministic signals that switch the rule on. Empty means unconstrained
    /// (no signal is required to activate); a non-empty list restricts
    /// activation to tasks carrying one of those signals. M2 selection logic
    /// must honor this empty-means-all contract.
    pub signals: Vec<String>,
}

/// How a rule is verified, and by which checks.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Enforcement {
    pub mode: EnforcementMode,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LanguageImplementation {
    pub mechanism: Mechanism,
    pub checks: Vec<String>,
    pub limitations: Vec<String>,
}

/// Evidence artifacts a task must produce for a rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub required: Vec<String>,
}

/// A single canonical engineering rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub mechanism: Mechanism,
    pub confidence: Confidence,
    pub examples: Vec<String>,
    pub limitations: Vec<String>,
    pub enforcement_stage: EnforcementStage,
    #[serde(default)]
    pub language_implementations: std::collections::BTreeMap<String, LanguageImplementation>,
    pub severity: Severity,
    pub level: Level,
    pub category: Category,
    pub applies_to: AppliesTo,
    pub activation: Activation,
    pub instruction: String,
    pub enforcement: Enforcement,
    pub overridable: bool,
    pub evidence: Evidence,
    pub references: Vec<String>,
}

/// Failure modes when loading and validating the registry.
///
/// Every variant's message ends without a trailing newline so callers can add
/// exactly one when printing. `SchemaViolations` lists each violation on its own
/// line and is deliberately newline-terminated by the final list entry.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// The embedded schema itself is not valid JSON or not a valid schema.
    #[error("embedded rule schema is invalid: {0}")]
    Schema(String),
    /// The registry text is not valid JSON.
    #[error("registry is not valid JSON: {0}")]
    RegistryJson(serde_json::Error),
    /// The registry does not satisfy the rule schema.
    #[error("{}", format_schema_violations(.0))]
    SchemaViolations(Vec<String>),
    /// Two or more rules share the same `id`. Rule IDs are the registry's
    /// primary key, so duplicates are rejected before deserialization.
    #[error(
        "duplicate rule id \"{id}\": defined at rule[{first_index}] and rule[{duplicate_index}]"
    )]
    DuplicateId {
        id: String,
        first_index: usize,
        duplicate_index: usize,
    },
    /// A capability declaration promises automation without a registered
    /// executable check, or declares an unsupported mechanism with checks.
    #[error("invalid capability for rule `{rule_id}`: {reason}")]
    CapabilityViolation { rule_id: String, reason: String },
    /// The registry is valid against the schema but does not deserialize into
    /// the rule model.
    ///
    /// This is defense against schema/struct drift: the schema is validated
    /// before this stage and is currently at least as strict as the typed model
    /// (the `Category` and `ChangeType` enums mirror the schema enums exactly),
    /// so a schema-valid registry always deserializes and this variant is
    /// unreachable in practice. It exists so that if the schema is ever loosened
    /// relative to the structs, the mismatch surfaces as a precise error instead
    /// of a panic.
    #[error("registry did not deserialize into the rule model: {0}")]
    Deserialize(serde_json::Error),
}

/// Render schema violations as a header line followed by one bullet per
/// violation. The result carries no trailing newline.
fn format_schema_violations(messages: &[String]) -> String {
    let mut rendered = String::from("registry failed schema validation:");
    for message in messages {
        rendered.push_str("\n  - ");
        rendered.push_str(message);
    }
    rendered
}

/// Validate arbitrary registry text against the embedded rule schema and
/// deserialize it into typed rules.
///
/// Validation happens in three ordered stages so failures are precise: the
/// registry must parse as JSON, satisfy the schema, then deserialize into the
/// rule model.
pub fn load_and_validate(registry_json: &str) -> Result<Vec<Rule>, RegistryError> {
    let schema_value: serde_json::Value = serde_json::from_str(RULE_SCHEMA_JSON)
        .map_err(|error| RegistryError::Schema(error.to_string()))?;

    let per_rule_validator = jsonschema::validator_for(&schema_value)
        .map_err(|error| RegistryError::Schema(error.to_string()))?;

    let registry_value: serde_json::Value =
        serde_json::from_str(registry_json).map_err(RegistryError::RegistryJson)?;

    let rules_array = registry_value.as_array().ok_or_else(|| {
        RegistryError::SchemaViolations(vec!["registry must be a JSON array".to_string()])
    })?;

    let mut violations = Vec::new();
    for (index, rule_value) in rules_array.iter().enumerate() {
        for error in per_rule_validator.iter_errors(rule_value) {
            violations.push(format!(
                "rule[{index}] at {}: {error}",
                error.instance_path()
            ));
        }
    }
    if !violations.is_empty() {
        return Err(RegistryError::SchemaViolations(violations));
    }

    check_unique_ids(rules_array)?;

    let rules: Vec<Rule> =
        serde_json::from_value(registry_value).map_err(RegistryError::Deserialize)?;
    validate_capabilities(&rules)?;
    Ok(rules)
}

fn validate_capabilities(rules: &[Rule]) -> Result<(), RegistryError> {
    for rule in rules {
        let automated = matches!(
            rule.mechanism,
            Mechanism::Native | Mechanism::Wrapped | Mechanism::Command
        );
        if automated && rule.enforcement.checks.is_empty() {
            return Err(RegistryError::CapabilityViolation {
                rule_id: rule.id.clone(),
                reason: "automated mechanism requires at least one registered check".to_string(),
            });
        }
        if automated
            && rule
                .enforcement
                .checks
                .iter()
                .any(|check| !registered_check(check))
        {
            return Err(RegistryError::CapabilityViolation {
                rule_id: rule.id.clone(),
                reason: "automated mechanism references an unknown check".to_string(),
            });
        }
        if matches!(rule.mechanism, Mechanism::Unsupported) && !rule.enforcement.checks.is_empty() {
            return Err(RegistryError::CapabilityViolation {
                rule_id: rule.id.clone(),
                reason: "unsupported mechanism cannot register executable checks".to_string(),
            });
        }
        for (language, implementation) in &rule.language_implementations {
            let automated = matches!(
                implementation.mechanism,
                Mechanism::Native | Mechanism::Wrapped | Mechanism::Command
            );
            if automated && implementation.checks.is_empty() {
                return Err(RegistryError::CapabilityViolation {
                    rule_id: rule.id.clone(),
                    reason: format!(
                        "language implementation `{language}` needs a registered check"
                    ),
                });
            }
            if automated
                && implementation
                    .checks
                    .iter()
                    .any(|check| !registered_check(check))
            {
                return Err(RegistryError::CapabilityViolation {
                    rule_id: rule.id.clone(),
                    reason: format!(
                        "language implementation `{language}` references an unknown check"
                    ),
                });
            }
        }
    }
    Ok(())
}

fn registered_check(check: &str) -> bool {
    matches!(
        check,
        "gitleaks.detect" | "ruff.check" | "command.required" | "git.diff" | "transcript.claims"
    ) || check.starts_with("semgrep.")
        || check.starts_with("native.")
}

/// Reject a registry in which two rules share the same `id`.
///
/// The per-rule schema cannot express a registry-wide uniqueness constraint, so
/// this runs after schema validation (where every `id` is guaranteed present and
/// a string) and before deserialization. The error names the duplicated ID and
/// both rule indices so the offending pair is unambiguous.
fn check_unique_ids(rules_array: &[serde_json::Value]) -> Result<(), RegistryError> {
    let mut first_seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (index, rule_value) in rules_array.iter().enumerate() {
        let Some(id) = rule_value.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if let Some(&first_index) = first_seen.get(id) {
            return Err(RegistryError::DuplicateId {
                id: id.to_string(),
                first_index,
                duplicate_index: index,
            });
        }
        first_seen.insert(id, index);
    }
    Ok(())
}

/// Validate and deserialize the embedded registry.
pub fn load_embedded_registry() -> Result<Vec<Rule>, RegistryError> {
    let rules = load_and_validate(RULES_JSON)?;
    profile::validate_embedded(&rules)
        .map_err(|message| RegistryError::SchemaViolations(vec![message]))?;
    Ok(rules)
}

pub type ResolvedRegistry = (
    String,
    Vec<Rule>,
    Vec<overrides::OverrideRecord>,
    Vec<waivers::Waiver>,
    config_version::Compatibility,
);

pub fn load_profiled_registry(root: &std::path::Path) -> Result<ResolvedRegistry, String> {
    let rules = load_embedded_registry().map_err(|error| error.to_string())?;
    let (name, compatibility) = profile::load_name(root)?;
    let mut resolved = profile::resolve(&name, &rules)?;
    let overrides = overrides::apply(root, &mut resolved)?;
    let waivers = waivers::load_active(root, &resolved)?;
    Ok((name, resolved, overrides, waivers, compatibility))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_registry_loads_and_validates() {
        let rules = load_embedded_registry().expect("embedded registry must validate");
        assert_eq!(rules.len(), 41);
    }

    #[test]
    fn embedded_registry_has_expected_stable_ids() {
        let rules = load_embedded_registry().expect("embedded registry must validate");
        let ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "no-committed-secrets",
                "no-swallowed-errors",
                "no-broad-exception-handling",
                "external-call-timeout",
                "public-input-validation",
                "sql-parameterization",
                "bounded-retries-loops",
                "destructive-operation-safeguards",
                "regression-test-required",
                "new-behavior-tests-required",
                "preserve-unrelated-user-changes",
                "new-dependency-review",
                "auth-change-security-review",
                "required-repository-commands",
                "evidence-claims-honest",
                "rust-no-unsafe",
                "rust-no-unwrap-expect",
                "typescript-no-any",
                "react-no-state-mutation",
                "react-unstable-key",
                "typescript-unsafe-unknown",
                "typescript-api-response-validation",
                "rust-spawn-cancellation",
                "rust-no-mutable-global",
                "react-effect-cleanup",
                "react-error-loading-states",
                "react-accessibility-review",
                "rust-async-timeout-review",
                "rust-id-unit-newtype-review",
                "go-ignored-error",
                "go-goroutine-cancellation",
                "go-mutable-global",
                "go-error-wrapping",
                "go-context-first-review",
                "function-size",
                "file-size",
                "function-complexity",
                "shell-safety-review",
                "shell-idempotency-review",
                "iac-validation-review",
                "config-schema-review",
            ]
        );
    }

    #[test]
    fn security_critical_rules_are_not_overridable() {
        let rules = load_embedded_registry().expect("embedded registry must validate");
        for rule in &rules {
            if matches!(
                rule.id.as_str(),
                "regression-test-required"
                    | "new-behavior-tests-required"
                    | "rust-no-unsafe"
                    | "rust-no-unwrap-expect"
                    | "rust-spawn-cancellation"
                    | "rust-no-mutable-global"
                    | "react-effect-cleanup"
                    | "react-error-loading-states"
                    | "react-accessibility-review"
                    | "rust-async-timeout-review"
                    | "rust-id-unit-newtype-review"
                    | "go-ignored-error"
                    | "go-goroutine-cancellation"
                    | "go-mutable-global"
                    | "go-error-wrapping"
                    | "go-context-first-review"
                    | "function-size"
                    | "file-size"
                    | "function-complexity"
                    | "shell-safety-review"
                    | "shell-idempotency-review"
                    | "iac-validation-review"
                    | "config-schema-review"
                    | "typescript-no-any"
                    | "typescript-unsafe-unknown"
                    | "typescript-api-response-validation"
                    | "react-no-state-mutation"
                    | "react-unstable-key"
            ) {
                assert!(rule.overridable);
                continue;
            }
            assert!(
                !rule.overridable,
                "seed MUST rule {} must be non-overridable",
                rule.id
            );
        }
    }
}
