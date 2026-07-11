use std::io::Read;
use std::path::Path;

const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_COMMANDS: usize = 64;
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const MAX_TIMEOUT_SECONDS: u64 = 3600;

#[derive(Debug)]
pub struct Settings {
    pub commands: Vec<String>,
    pub timeout: std::time::Duration,
}

pub fn load(root: &Path) -> Result<Settings, String> {
    let path = root.join(".lgtm/config.json");
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.is_file() => {
            return Err("config is not a regular file".to_string());
        }
        Ok(metadata) if metadata.len() > MAX_CONFIG_BYTES => {
            return Err(format!("config exceeds {MAX_CONFIG_BYTES} bytes"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(defaults()),
        Err(error) => return Err(format!("inspect config ({error})")),
    }
    let Some(file) = crate::fsutil::open_regular_file(&path)
        .map_err(|error| format!("open config ({error})"))?
    else {
        return Err("config could not be opened as a regular file".to_string());
    };
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| format!("read config ({error})"))?;
    if raw.len() as u64 > MAX_CONFIG_BYTES {
        return Err(format!("config exceeds {MAX_CONFIG_BYTES} bytes"));
    }
    if raw.trim().is_empty() {
        return Ok(defaults());
    }
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|error| format!("parse required commands ({error})"))?;
    let timeout = timeout(&value)?;
    let Some(required) = value.get("required_commands") else {
        return Ok(Settings {
            commands: Vec::new(),
            timeout,
        });
    };
    let map = required
        .as_object()
        .ok_or_else(|| "required_commands must be an object".to_string())?;
    let mut commands = Vec::new();
    for values in map.values() {
        let values = values
            .as_array()
            .ok_or_else(|| "required command group must be an array".to_string())?;
        for value in values {
            let command = value
                .as_str()
                .ok_or_else(|| "required command must be a string".to_string())?;
            commands.push(command.to_string());
            if commands.len() > MAX_COMMANDS {
                return Err(format!("required_commands exceeds {MAX_COMMANDS} commands"));
            }
        }
    }
    Ok(Settings { commands, timeout })
}

fn defaults() -> Settings {
    Settings {
        commands: Vec::new(),
        timeout: std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
    }
}

fn timeout(value: &serde_json::Value) -> Result<std::time::Duration, String> {
    let seconds = match value.get("command_timeout_seconds") {
        None => DEFAULT_TIMEOUT_SECONDS,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| "command_timeout_seconds must be an integer".to_string())?,
    };
    if !(1..=MAX_TIMEOUT_SECONDS).contains(&seconds) {
        return Err(format!(
            "command_timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}"
        ));
    }
    Ok(std::time::Duration::from_secs(seconds))
}
