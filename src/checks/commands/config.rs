use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_COMMANDS: usize = 64;
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const MAX_TIMEOUT_SECONDS: u64 = 3600;

#[derive(Debug)]
pub struct Settings {
    pub commands: Vec<String>,
    pub structured: Vec<StructuredCommand>,
    pub timeout: std::time::Duration,
    pub coverage: Vec<CoverageCommand>,
}

#[derive(Debug, Clone)]
pub struct StructuredCommand {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub workspace_id: String,
    pub tier: String,
    pub timeout: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct CoverageCommand {
    pub workspace_id: String,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub timeout: std::time::Duration,
    pub scope: String,
    pub line_threshold_percent: Option<u8>,
    pub branch_threshold_percent: Option<u8>,
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
        Ok(metadata) => {
            #[cfg(unix)]
            {
                // The process owner check uses the kernel effective UID; no
                // memory or pointer is passed, so this libc call is safe.
                let foreign_owner = metadata.uid() != unsafe { libc::geteuid() };
                let world_writable = metadata.permissions().mode() & 0o002 != 0;
                if foreign_owner || world_writable {
                    return Err(
                        "config must be owned by the runner and not world writable".to_string()
                    );
                }
            }
        }
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
    if value.get("version").and_then(serde_json::Value::as_str) == Some(crate::config_v2::VERSION) {
        let config = crate::config_v2::parse(&value).map_err(|error| error.to_string())?;
        let mut commands = Vec::new();
        let mut structured = Vec::new();
        let mut coverage = Vec::new();
        for workspace in config.workspaces {
            for item in &workspace.coverage {
                coverage.push(CoverageCommand {
                    workspace_id: workspace.id.clone(),
                    argv: item.argv.clone(),
                    cwd: item.cwd.clone(),
                    timeout: std::time::Duration::from_secs(item.timeout_seconds),
                    scope: item.scope.clone(),
                    line_threshold_percent: item.line_threshold_percent,
                    branch_threshold_percent: item.branch_threshold_percent,
                });
            }
            for command in workspace.commands {
                commands.push(command.argv.join(" "));
                structured.push(StructuredCommand {
                    argv: command.argv,
                    cwd: command.cwd,
                    workspace_id: workspace.id.clone(),
                    tier: command.tier,
                    timeout: std::time::Duration::from_secs(command.timeout_seconds),
                });
            }
        }
        if commands.len() > MAX_COMMANDS {
            return Err(format!("workspaces exceed {MAX_COMMANDS} commands"));
        }
        return Ok(Settings {
            commands,
            structured,
            timeout: std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
            coverage,
        });
    }
    let timeout = timeout(&value)?;
    let Some(required) = value.get("required_commands") else {
        return Ok(Settings {
            commands: Vec::new(),
            structured: Vec::new(),
            timeout,
            coverage: Vec::new(),
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
    Ok(Settings {
        commands,
        structured: Vec::new(),
        timeout,
        coverage: Vec::new(),
    })
}

fn defaults() -> Settings {
    Settings {
        commands: Vec::new(),
        structured: Vec::new(),
        timeout: std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
        coverage: Vec::new(),
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
