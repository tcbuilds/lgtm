//! Structured, shell-free repository configuration (V2).

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::discovery::{CommandSpec, Workspace};

pub const VERSION: &str = "2";
pub const SCHEMA_JSON: &str = include_str!("../policy/config-v2.schema.json");
const SCHEMA_ERROR_PATH_MAX_BYTES: usize = 128;
const SCHEMA_ERROR_MESSAGE_MAX_BYTES: usize = 256;
const CONFIG_DIAGNOSTIC_MAX_BYTES: usize = 2048;
pub const MAX_WORKSPACES: usize = 64;
pub const MAX_STRUCTURED_COMMANDS: usize = 64;
pub const MAX_COVERAGE_COMMANDS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigV2 {
    pub version: String,
    pub profile: String,
    pub workspaces: Vec<Workspace>,
    pub disabled_rules: Vec<String>,
    pub severity_overrides: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum ConfigV2Error {
    #[error("config V2 schema is invalid: {0}")]
    Schema(String),
    #[error("config V2 JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("config V2 is invalid: {0}")]
    Invalid(String),
}

pub fn parse(value: &Value) -> Result<ConfigV2, ConfigV2Error> {
    let schema: Value = serde_json::from_str(SCHEMA_JSON)
        .map_err(|error| ConfigV2Error::Schema(error.to_string()))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| ConfigV2Error::Schema(error.to_string()))?;
    let mut diagnostic = SanitizedBoundedString::new(CONFIG_DIAGNOSTIC_MAX_BYTES);
    let mut has_errors = false;
    for error in validator.iter_errors(value) {
        if has_errors && write!(diagnostic, "; ").is_err() {
            break;
        }
        has_errors = true;

        let path =
            sanitize_and_truncate(error.instance_path().as_str(), SCHEMA_ERROR_PATH_MAX_BYTES);
        if !path.is_empty() && write!(diagnostic, "{path}: ").is_err() {
            break;
        }
        let message = format_bounded(&error, SCHEMA_ERROR_MESSAGE_MAX_BYTES);
        if write!(diagnostic, "{message}").is_err() {
            break;
        }
    }
    if has_errors {
        return Err(ConfigV2Error::Invalid(diagnostic.finish()));
    }
    let config: ConfigV2 = serde_json::from_value(value.clone())?;
    validate(&config)?;
    Ok(config)
}

pub fn validate(config: &ConfigV2) -> Result<(), ConfigV2Error> {
    if config.version != VERSION {
        return Err(ConfigV2Error::Invalid(format!(
            "expected version {VERSION}, found {}",
            config.version
        )));
    }
    if config
        .severity_overrides
        .values()
        .any(|severity| !matches!(severity.as_str(), "error" | "warning" | "info"))
    {
        return Err(ConfigV2Error::Invalid(
            "severity_overrides values must be one of: error, warning, info".to_string(),
        ));
    }
    if config.workspaces.len() > MAX_WORKSPACES {
        return Err(ConfigV2Error::Invalid(format!(
            "config V2 contains more than {MAX_WORKSPACES} workspaces"
        )));
    }
    let structured_count = config
        .workspaces
        .iter()
        .map(|workspace| workspace.commands.len())
        .sum::<usize>();
    if structured_count > MAX_STRUCTURED_COMMANDS {
        return Err(ConfigV2Error::Invalid(format!(
            "config V2 contains more than {MAX_STRUCTURED_COMMANDS} structured commands"
        )));
    }
    let coverage_count = config
        .workspaces
        .iter()
        .map(|workspace| workspace.coverage.len())
        .sum::<usize>();
    if coverage_count > MAX_COVERAGE_COMMANDS {
        return Err(ConfigV2Error::Invalid(format!(
            "config V2 contains more than {MAX_COVERAGE_COMMANDS} coverage commands"
        )));
    }
    for workspace in &config.workspaces {
        validate_relative_path(&workspace.root, "workspace root")?;
        for command in &workspace.commands {
            if command.argv.is_empty() {
                return Err(ConfigV2Error::Invalid(format!(
                    "workspace `{}` contains an empty argv",
                    workspace.id
                )));
            }
            validate_relative_path(&command.cwd, "command cwd")?;
            if !(1..=3600).contains(&command.timeout_seconds) {
                return Err(ConfigV2Error::Invalid(format!(
                    "workspace `{}` has an invalid timeout",
                    workspace.id
                )));
            }
            if command.argv.iter().any(|arg| contains_shell_operator(arg)) {
                return Err(ConfigV2Error::Invalid(format!(
                    "workspace `{}` command contains a shell operator",
                    workspace.id
                )));
            }
        }
        for coverage in &workspace.coverage {
            if coverage.argv.is_empty() {
                return Err(ConfigV2Error::Invalid(format!(
                    "workspace `{}` contains an empty coverage argv",
                    workspace.id
                )));
            }
            validate_relative_path(&coverage.cwd, "coverage cwd")?;
            if !(1..=3600).contains(&coverage.timeout_seconds) {
                return Err(ConfigV2Error::Invalid(format!(
                    "workspace `{}` has an invalid coverage timeout",
                    workspace.id
                )));
            }
            if coverage.argv.iter().any(|arg| contains_shell_operator(arg)) {
                return Err(ConfigV2Error::Invalid(format!(
                    "workspace `{}` coverage command contains a shell operator",
                    workspace.id
                )));
            }
            if coverage
                .line_threshold_percent
                .is_some_and(|value| value > 100)
                || coverage
                    .branch_threshold_percent
                    .is_some_and(|value| value > 100)
            {
                return Err(ConfigV2Error::Invalid(format!(
                    "workspace `{}` has an invalid coverage threshold",
                    workspace.id
                )));
            }
        }
    }
    Ok(())
}

/// Convert a validated V1 object into V2 without interpreting shell syntax.
pub fn migrate_v1(value: &Value) -> Result<ConfigV2, ConfigV2Error> {
    let object = value
        .as_object()
        .ok_or_else(|| ConfigV2Error::Invalid("V1 config must be an object".to_string()))?;
    let profile = object
        .get("profile")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();
    let disabled_rules = string_array(object, "disabled_rules")?;
    let severity_overrides = object
        .get("severity_overrides")
        .map(string_map)
        .transpose()?
        .unwrap_or_default();
    let required = object
        .get("required_commands")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ConfigV2Error::Invalid("V1 required_commands must be an object".to_string())
        })?;

    let mut workspaces = Vec::new();
    for (language, commands) in required {
        let commands = commands.as_array().ok_or_else(|| {
            ConfigV2Error::Invalid(format!("V1 commands for `{language}` must be an array"))
        })?;
        let mut specs = Vec::new();
        for command in commands {
            let shell = command.as_str().ok_or_else(|| {
                ConfigV2Error::Invalid(format!("V1 command for `{language}` must be a string"))
            })?;
            let argv = split_shell_free(shell)?;
            specs.push(CommandSpec {
                argv,
                cwd: ".".into(),
                timeout_seconds: 300,
                tier: "full".to_string(),
                purpose: "migrated quality gate".to_string(),
                source: "v1-migration".to_string(),
                confidence: "medium".to_string(),
            });
        }
        workspaces.push(Workspace {
            id: language.clone(),
            language: language.clone(),
            root: ".".into(),
            commands: specs,
            coverage: Vec::new(),
        });
    }
    let config = ConfigV2 {
        version: VERSION.to_string(),
        profile,
        workspaces,
        disabled_rules,
        severity_overrides,
    };
    validate(&config)?;
    Ok(config)
}

/// Migrate legacy commands while replacing guessed root gates with detected
/// workspace-scoped commands. User policy fields remain preserved.
pub fn migrate_v1_with_workspaces(
    value: &Value,
    detected: &[Workspace],
) -> Result<ConfigV2, ConfigV2Error> {
    let mut config = migrate_v1(value)?;
    if !detected.is_empty() {
        config.workspaces = detected.to_vec();
        for workspace in &mut config.workspaces {
            for command in &mut workspace.commands {
                command.source = "discovery-migration".to_string();
            }
        }
    }
    validate(&config)?;
    Ok(config)
}

pub fn render(config: &ConfigV2) -> Result<Vec<u8>, ConfigV2Error> {
    validate(config)?;
    let mut rendered = serde_json::to_string_pretty(config)?;
    rendered.push('\n');
    Ok(rendered.into_bytes())
}

fn string_array(object: &Map<String, Value>, field: &str) -> Result<Vec<String>, ConfigV2Error> {
    object
        .get(field)
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| ConfigV2Error::Invalid(format!("V1 {field} must be an array")))?
                .iter()
                .map(|value| {
                    value.as_str().map(str::to_string).ok_or_else(|| {
                        ConfigV2Error::Invalid(format!("V1 {field} must contain strings"))
                    })
                })
                .collect()
        })
        .transpose()
        .map(|value| value.unwrap_or_default())
}

fn string_map(value: &Value) -> Result<BTreeMap<String, String>, ConfigV2Error> {
    value
        .as_object()
        .ok_or_else(|| {
            ConfigV2Error::Invalid("V1 severity_overrides must be an object".to_string())
        })?
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_string()))
                .ok_or_else(|| {
                    ConfigV2Error::Invalid(
                        "V1 severity_overrides values must be strings".to_string(),
                    )
                })
        })
        .collect()
}

fn split_shell_free(command: &str) -> Result<Vec<String>, ConfigV2Error> {
    if command.trim().is_empty() || contains_shell_operator(command) {
        return Err(ConfigV2Error::Invalid(format!(
            "cannot migrate shell command `{}` without interpreting shell syntax",
            command
                .chars()
                .filter(|character| !character.is_control())
                .take(80)
                .collect::<String>()
        )));
    }
    Ok(command.split_whitespace().map(str::to_string).collect())
}

fn contains_shell_operator(character: &str) -> bool {
    character.chars().any(|character| {
        matches!(
            character,
            '|' | '&' | ';' | '<' | '>' | '$' | '`' | '(' | ')' | '\n' | '\r'
        )
    })
}

pub fn sanitize_config_diagnostic(value: impl fmt::Display) -> String {
    format_bounded(&value, CONFIG_DIAGNOSTIC_MAX_BYTES)
}

fn sanitize_and_truncate(value: &str, max_bytes: usize) -> String {
    format_bounded(&value, max_bytes)
}

fn format_bounded(value: &impl fmt::Display, max_bytes: usize) -> String {
    let mut rendered = SanitizedBoundedString::new(max_bytes);
    let _ = write!(rendered, "{value}");
    rendered.finish()
}

struct SanitizedBoundedString {
    value: String,
    max_bytes: usize,
    truncated: bool,
}

impl SanitizedBoundedString {
    fn new(max_bytes: usize) -> Self {
        Self {
            value: String::with_capacity(max_bytes),
            max_bytes,
            truncated: false,
        }
    }

    fn finish(mut self) -> String {
        if !self.truncated {
            return self.value;
        }

        let ellipsis = "…";
        if self.max_bytes < ellipsis.len() {
            self.value.clear();
            return self.value;
        }
        let content_limit = self.max_bytes - ellipsis.len();
        let mut end = content_limit.min(self.value.len());
        while !self.value.is_char_boundary(end) {
            end -= 1;
        }
        self.value.truncate(end);
        self.value.push_str(ellipsis);
        self.value
    }
}

impl fmt::Write for SanitizedBoundedString {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for character in value.chars().filter(|character| !character.is_control()) {
            if self.value.len() + character.len_utf8() > self.max_bytes {
                self.truncated = true;
                return Err(fmt::Error);
            }
            self.value.push(character);
        }
        Ok(())
    }
}

fn validate_relative_path(path: &Path, label: &str) -> Result<(), ConfigV2Error> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigV2Error::Invalid(format!(
            "{label} must be repository-relative"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::CoverageSpec;
    use serde_json::json;

    #[test]
    fn migrates_v1_commands_to_structured_argv() {
        let value = json!({
            "profile": "strict",
            "disabled_rules": ["example"],
            "severity_overrides": {"example": "warning"},
            "required_commands": {"python": ["uv run pytest", "ruff check ."]}
        });
        let config = migrate_v1(&value).expect("migration succeeds");
        assert_eq!(config.version, VERSION);
        assert_eq!(
            config.workspaces[0].commands[0].argv,
            ["uv", "run", "pytest"]
        );
        assert_eq!(config.workspaces[0].commands[0].source, "v1-migration");
    }

    #[test]
    fn refuses_shell_operators_in_v1_commands() {
        let value = json!({"required_commands": {"python": ["pytest | tee log"]}});
        let error = migrate_v1(&value).expect_err("shell syntax must be refused");
        assert!(
            error
                .to_string()
                .contains("without interpreting shell syntax")
        );
    }

    #[test]
    fn refuses_unsupported_v1_severity_during_migration() {
        let value = json!({
            "severity_overrides": {"regression-test-required": "critical"},
            "required_commands": {"rust": ["cargo test"]}
        });
        let error = migrate_v1(&value).expect_err("unsupported severity must be refused");
        assert!(
            error
                .to_string()
                .contains("severity_overrides values must be one of: error, warning, info")
        );
    }

    #[test]
    fn diagnostic_sanitizer_streams_into_a_fixed_budget() {
        struct HostileDiagnostic;

        impl fmt::Display for HostileDiagnostic {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for _ in 0..CONFIG_DIAGNOSTIC_MAX_BYTES {
                    formatter.write_str("payload\u{0007}—")?;
                }
                Ok(())
            }
        }

        let diagnostic = sanitize_config_diagnostic(HostileDiagnostic);
        assert!(diagnostic.len() <= CONFIG_DIAGNOSTIC_MAX_BYTES);
        assert!(!diagnostic.chars().any(char::is_control));
        assert!(diagnostic.ends_with('…'));
    }

    fn workspace(
        index: usize,
        commands: Vec<CommandSpec>,
        coverage: Vec<CoverageSpec>,
    ) -> Workspace {
        Workspace {
            id: format!("workspace-{index}"),
            language: "shell".to_string(),
            root: Path::new(".").to_path_buf(),
            commands,
            coverage,
        }
    }

    fn command_spec() -> CommandSpec {
        CommandSpec {
            argv: vec!["true".to_string()],
            cwd: Path::new(".").to_path_buf(),
            timeout_seconds: 30,
            tier: "full".to_string(),
            purpose: "test".to_string(),
            source: "fixture".to_string(),
            confidence: "high".to_string(),
        }
    }

    fn coverage_spec() -> CoverageSpec {
        CoverageSpec {
            argv: vec!["true".to_string()],
            cwd: Path::new(".").to_path_buf(),
            timeout_seconds: 30,
            scope: "unit".to_string(),
            line_threshold_percent: None,
            branch_threshold_percent: None,
        }
    }

    fn config(workspaces: Vec<Workspace>) -> ConfigV2 {
        ConfigV2 {
            version: VERSION.to_string(),
            profile: "default".to_string(),
            workspaces,
            disabled_rules: Vec::new(),
            severity_overrides: BTreeMap::new(),
        }
    }

    #[test]
    fn accepts_exact_v2_workspace_and_aggregate_command_limits() {
        let workspaces = (0..MAX_WORKSPACES)
            .map(|index| workspace(index, Vec::new(), Vec::new()))
            .collect();
        assert!(validate(&config(workspaces)).is_ok());

        let structured_at_limit = config(vec![
            workspace(
                0,
                vec![command_spec(); MAX_STRUCTURED_COMMANDS / 2],
                Vec::new(),
            ),
            workspace(
                1,
                vec![command_spec(); MAX_STRUCTURED_COMMANDS / 2],
                Vec::new(),
            ),
        ]);
        assert!(validate(&structured_at_limit).is_ok());

        let coverage_at_limit = config(vec![
            workspace(
                0,
                Vec::new(),
                vec![coverage_spec(); MAX_COVERAGE_COMMANDS / 2],
            ),
            workspace(
                1,
                Vec::new(),
                vec![coverage_spec(); MAX_COVERAGE_COMMANDS / 2],
            ),
        ]);
        assert!(validate(&coverage_at_limit).is_ok());
    }

    #[test]
    fn rejects_the_first_v2_workspace_or_aggregate_command_over_limit() {
        let mut too_many_workspaces = (0..MAX_WORKSPACES)
            .map(|index| workspace(index, Vec::new(), Vec::new()))
            .collect::<Vec<_>>();
        too_many_workspaces.push(workspace(MAX_WORKSPACES, Vec::new(), Vec::new()));
        let error = validate(&config(too_many_workspaces)).expect_err("workspace cap");
        assert!(error.to_string().contains("64 workspaces"));

        let mut too_many_structured = vec![
            workspace(
                0,
                vec![command_spec(); MAX_STRUCTURED_COMMANDS / 2],
                Vec::new(),
            ),
            workspace(
                1,
                vec![command_spec(); MAX_STRUCTURED_COMMANDS / 2],
                Vec::new(),
            ),
        ];
        too_many_structured[1].commands.push(command_spec());
        let error = validate(&config(too_many_structured)).expect_err("structured cap");
        assert!(error.to_string().contains("64 structured commands"));

        let mut too_many_coverage = vec![
            workspace(
                0,
                Vec::new(),
                vec![coverage_spec(); MAX_COVERAGE_COMMANDS / 2],
            ),
            workspace(
                1,
                Vec::new(),
                vec![coverage_spec(); MAX_COVERAGE_COMMANDS / 2],
            ),
        ];
        too_many_coverage[1].coverage.push(coverage_spec());
        let error = validate(&config(too_many_coverage)).expect_err("coverage cap");
        assert!(error.to_string().contains("64 coverage commands"));
    }
}
