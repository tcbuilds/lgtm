//! Structured, shell-free repository configuration (V2).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::discovery::{CommandSpec, Workspace};

pub const VERSION: &str = "2";
pub const SCHEMA_JSON: &str = include_str!("../policy/config-v2.schema.json");

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
    let errors: Vec<_> = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect();
    if !errors.is_empty() {
        return Err(ConfigV2Error::Invalid(errors.join("; ")));
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
}
