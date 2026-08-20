use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use super::command::ProhibitedMatch;
use crate::fsutil::open_regular_file;

const MAX_CONFIG_BYTES: u64 = 256 * 1_024;

pub(super) fn require_policy_files(root: &Path) -> Result<(), String> {
    for name in ["config.json", "execpolicy.json"] {
        let path = root.join(".lgtm").join(name);
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|_| format!("{name} policy is missing"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!("{name} policy is not a regular file"));
        }
    }
    Ok(())
}

#[derive(Debug, Default, Deserialize)]
struct Config {
    #[serde(default)]
    prohibited_paths: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ExecPolicy {
    #[serde(default)]
    prohibited_commands: Vec<Vec<String>>,
}

pub(super) fn validate_policy_files(root: &Path) -> Result<(), String> {
    require_policy_files(root)?;
    let config_path = root.join(".lgtm/config.json");
    let config_file = open_regular_file(&config_path)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "config policy is missing".to_string())?;
    let mut config_raw = String::new();
    config_file
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut config_raw)
        .map_err(|error| error.to_string())?;
    if config_raw.len() as u64 > MAX_CONFIG_BYTES {
        return Err("config exceeds maximum size".to_string());
    }
    let config_value: serde_json::Value =
        serde_json::from_str(&config_raw).map_err(|error| error.to_string())?;
    if config_value.get("version").is_some() {
        crate::config_v2::parse(&config_value).map_err(|error| error.to_string())?;
    } else {
        crate::config_v2::validate_legacy(&config_value).map_err(|error| error.to_string())?;
    }
    validate_execpolicy_file(root)?;
    prohibited_patterns(root)?;
    match_prohibited_command(root, "")?;
    Ok(())
}

fn validate_execpolicy_file(root: &Path) -> Result<(), String> {
    let path = root.join(".lgtm/execpolicy.json");
    let file = open_regular_file(&path)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "execpolicy policy is missing".to_string())?;
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| error.to_string())?;
    if raw.len() as u64 > MAX_CONFIG_BYTES {
        return Err("execpolicy exceeds maximum size".to_string());
    }
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|error| error.to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "execpolicy must be an object".to_string())?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "prohibited_commands" | "prohibited_paths"))
    {
        return Err("execpolicy contains an unsupported field".to_string());
    }
    if let Some(commands) = object.get("prohibited_commands") {
        let commands = commands
            .as_array()
            .ok_or_else(|| "prohibited_commands must be an array".to_string())?;
        if commands.len() > 256
            || commands.iter().any(|command| {
                let Some(argv) = command.as_array() else {
                    return true;
                };
                argv.is_empty()
                    || argv.len() > 32
                    || argv.iter().any(|item| {
                        item.as_str().is_none_or(|item| {
                            item.is_empty()
                                || item.len() > 4096
                                || item.chars().any(char::is_control)
                        })
                    })
            })
        {
            return Err("prohibited_commands contains an invalid entry".to_string());
        }
    }
    if let Some(paths) = object.get("prohibited_paths") {
        let paths = paths
            .as_array()
            .ok_or_else(|| "prohibited_paths must be an array".to_string())?;
        if paths.len() > 256
            || paths.iter().any(|path| {
                path.as_str().is_none_or(|path| {
                    path.is_empty()
                        || path.len() > 4096
                        || path.starts_with('/')
                        || path.split('/').any(|part| part == "..")
                        || path.chars().any(char::is_control)
                })
            })
        {
            return Err("prohibited_paths contains an invalid entry".to_string());
        }
    }
    Ok(())
}

pub(super) fn prohibited_patterns(root: &Path) -> Result<Vec<String>, String> {
    let path = root.join(".lgtm/config.json");
    if std::fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
        return Err("config is not a regular file".to_string());
    }
    let Some(file) = open_regular_file(&path).map_err(|error| error.to_string())? else {
        return Ok(Vec::new());
    };
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| error.to_string())?;
    if raw.len() as u64 > MAX_CONFIG_BYTES {
        return Err("config exceeds maximum size".to_string());
    }
    let config: Config = serde_json::from_str(&raw).map_err(|error| error.to_string())?;
    if config.prohibited_paths.len() > 1_024 {
        return Err("prohibited_paths exceeds bounds".to_string());
    }
    config
        .prohibited_paths
        .into_iter()
        .map(normalize_pattern)
        .collect()
}

pub(super) fn is_prohibited(relative: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        if matches!(pattern.as_str(), "*" | "**") {
            return true;
        }
        let Some(prefix) = pattern.strip_suffix("/**") else {
            return relative == pattern;
        };
        relative == prefix || relative.starts_with(&format!("{prefix}/"))
    })
}

/// Load `.lgtm/execpolicy.json` and match one shell command against it.
///
/// Returns `Ok(None)` when the command is allowed, including when the
/// repository has no policy at all. Matching itself lives in
/// [`super::command`]; this function owns only the bounded read and parse.
pub(super) fn match_prohibited_command(
    root: &Path,
    command: &str,
) -> Result<Option<ProhibitedMatch>, String> {
    let path = root.join(".lgtm/execpolicy.json");
    if std::fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
        return Err("execpolicy is not a regular file".to_string());
    }
    let Some(file) = open_regular_file(&path).map_err(|error| error.to_string())? else {
        return Ok(None);
    };
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| error.to_string())?;
    if raw.len() as u64 > MAX_CONFIG_BYTES {
        return Err("execpolicy exceeds maximum size".to_string());
    }
    let policy: ExecPolicy = serde_json::from_str(&raw).map_err(|error| error.to_string())?;
    if policy.prohibited_commands.len() > 256 {
        return Err("prohibited_commands exceeds bounds".to_string());
    }
    let argv = shlex::split(command).ok_or_else(|| "command has invalid quoting".to_string())?;
    Ok(super::command::find_match(
        &argv,
        &policy.prohibited_commands,
    ))
}

fn normalize_pattern(pattern: String) -> Result<String, String> {
    let pattern = pattern.replace('\\', "/");
    let core = pattern.strip_suffix("/**").unwrap_or(&pattern);
    let is_all = matches!(pattern.as_str(), "*" | "**");
    if pattern.is_empty()
        || pattern.len() > 4_096
        || core.starts_with('/')
        || core.split('/').any(|part| matches!(part, "" | "." | ".."))
        || (!is_all && core.contains('*'))
    {
        return Err("prohibited_paths contains an invalid pattern".to_string());
    }
    Ok(pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("lgtm-pre-config-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".lgtm")).expect("root");
        root
    }

    fn padded_json(limit: usize) -> String {
        let prefix = r#"{"padding":""#;
        let suffix = r#""}"#;
        format!(
            "{prefix}{}{suffix}",
            "a".repeat(limit - prefix.len() - suffix.len())
        )
    }

    #[test]
    fn exact_prefix_and_all_patterns_match_explicitly() {
        assert!(is_prohibited("secrets/key.py", &["secrets/**".to_string()]));
        assert!(is_prohibited("secrets", &["secrets/**".to_string()]));
        assert!(!is_prohibited("secret", &["secrets/**".to_string()]));
        assert!(is_prohibited("config.json", &["config.json".to_string()]));
        assert!(is_prohibited("any/path", &["*".to_string()]));
        assert!(!is_prohibited("config.toml", &["config.json".to_string()]));
    }

    #[test]
    fn unsupported_or_traversing_patterns_are_rejected() {
        for pattern in ["*.env", "../secret", "/etc", ""] {
            assert!(normalize_pattern(pattern.to_string()).is_err(), "{pattern}");
        }
    }

    #[test]
    fn wildcard_patterns_are_valid_only_as_global_patterns() {
        assert!(normalize_pattern("*".to_string()).is_ok());
        assert!(normalize_pattern("**".to_string()).is_ok());
        assert!(normalize_pattern("dir/*".to_string()).is_err());
    }

    #[test]
    fn pattern_length_boundary_is_explicit() {
        assert!(normalize_pattern("a".repeat(4_096)).is_ok());
        assert!(normalize_pattern("a".repeat(4_097)).is_err());
    }

    #[test]
    fn prohibited_path_config_enforces_byte_and_entry_limits() {
        let root = temp_root("paths");
        let path = root.join(".lgtm/config.json");
        let limit = 256 * 1_024;
        std::fs::write(&path, padded_json(limit)).expect("config");
        assert!(prohibited_patterns(&root).is_ok());
        let mut oversized = padded_json(limit);
        oversized.push(' ');
        std::fs::write(&path, oversized).expect("oversized config");
        assert!(prohibited_patterns(&root).is_err());

        let entries = (0..1_024).map(|_| "path").collect::<Vec<_>>();
        std::fs::write(
            &path,
            serde_json::json!({"prohibited_paths": entries}).to_string(),
        )
        .expect("bounded entries");
        assert!(prohibited_patterns(&root).is_ok());
        let entries = (0..1_025).map(|_| "path").collect::<Vec<_>>();
        std::fs::write(
            &path,
            serde_json::json!({"prohibited_paths": entries}).to_string(),
        )
        .expect("too many entries");
        assert!(prohibited_patterns(&root).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn prohibited_command_config_enforces_byte_and_entry_limits() {
        let root = temp_root("commands");
        let path = root.join(".lgtm/execpolicy.json");
        let limit = 256 * 1_024;
        std::fs::write(&path, padded_json(limit)).expect("policy");
        assert!(match_prohibited_command(&root, "echo ok").is_ok());
        let mut oversized = padded_json(limit);
        oversized.push(' ');
        std::fs::write(&path, oversized).expect("oversized policy");
        assert!(match_prohibited_command(&root, "echo ok").is_err());

        let entries = (0..256)
            .map(|index| vec!["echo".to_string(), format!("arg{index}")])
            .collect::<Vec<_>>();
        std::fs::write(
            &path,
            serde_json::json!({"prohibited_commands": entries}).to_string(),
        )
        .expect("bounded policy");
        assert!(match_prohibited_command(&root, "echo ok").is_ok());
        let entries = (0..257)
            .map(|index| vec!["echo".to_string(), format!("arg{index}")])
            .collect::<Vec<_>>();
        std::fs::write(
            &path,
            serde_json::json!({"prohibited_commands": entries}).to_string(),
        )
        .expect("too many commands");
        assert!(match_prohibited_command(&root, "echo ok").is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
