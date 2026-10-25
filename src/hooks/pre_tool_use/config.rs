use std::io::Read;
use std::path::Path;

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
