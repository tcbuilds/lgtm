//! Export the exact embedded policy bundle for inspection and CI pinning.

use std::fs;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

const ARTIFACTS: [(&str, &str); 10] = [
    ("rules.json", super::RULES_JSON),
    ("rule.schema.json", super::RULE_SCHEMA_JSON),
    ("standards-coverage.json", super::coverage::COVERAGE_JSON),
    (
        "standards-coverage.schema.json",
        super::coverage::COVERAGE_SCHEMA_JSON,
    ),
    ("config-v2.schema.json", crate::config_v2::SCHEMA_JSON),
    (
        "semgrep-python.yml",
        include_str!("../../policy/semgrep-python.yml"),
    ),
    (
        "profiles/default.json",
        include_str!("../../policy/profiles/default.json"),
    ),
    (
        "profiles/strict.json",
        include_str!("../../policy/profiles/strict.json"),
    ),
    (
        "profiles/prototype.json",
        include_str!("../../policy/profiles/prototype.json"),
    ),
    (
        "profiles/infrastructure.json",
        include_str!("../../policy/profiles/infrastructure.json"),
    ),
];

#[derive(Debug, Serialize)]
struct Manifest {
    binary_version: &'static str,
    policy_version: &'static str,
    files: Vec<FileDigest>,
}

#[derive(Debug, Serialize)]
struct FileDigest {
    path: String,
    sha256: String,
    bytes: usize,
}

pub fn run(output: &Path, force: bool) -> Result<String, String> {
    if output.as_os_str().is_empty() || output == Path::new(".") {
        return Err("export output must be a dedicated directory".to_string());
    }
    if output.components().count() < 2 {
        return Err("export output must not be a filesystem root".to_string());
    }
    if output.exists() {
        let metadata = fs::symlink_metadata(output)
            .map_err(|error| format!("inspect export output ({error})"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("export output must be a real directory".to_string());
        }
    }
    if output.exists() && !force {
        return Err(format!(
            "export output already exists: {} (pass --force to replace it)",
            output.display()
        ));
    }
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("create export parent ({error})"))?;
    let temp = parent.join(format!(".lgtm-export-{}", std::process::id()));
    if temp.exists() {
        fs::remove_dir_all(&temp).map_err(|error| format!("clear export staging ({error})"))?;
    }
    fs::create_dir_all(&temp).map_err(|error| format!("create export staging ({error})"))?;

    let mut files = Vec::new();
    for (relative, contents) in ARTIFACTS {
        let path = temp.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create artifact parent ({error})"))?;
        }
        fs::write(&path, contents).map_err(|error| format!("write {relative} ({error})"))?;
        files.push(FileDigest {
            path: relative.to_string(),
            sha256: digest(contents.as_bytes()),
            bytes: contents.len(),
        });
    }
    let manifest = Manifest {
        binary_version: env!("CARGO_PKG_VERSION"),
        policy_version: "V2",
        files,
    };
    let manifest_text = serde_json::to_string_pretty(&manifest)
        .map_err(|error| format!("serialize export manifest ({error})"))?;
    fs::write(temp.join("manifest.json"), format!("{manifest_text}\n"))
        .map_err(|error| format!("write manifest ({error})"))?;

    if output.exists() {
        if !force {
            return Err(format!(
                "export output already exists: {}",
                output.display()
            ));
        }
        fs::remove_dir_all(output).map_err(|error| format!("replace export output ({error})"))?;
    }
    fs::rename(&temp, output).map_err(|error| format!("publish export atomically ({error})"))?;
    Ok(format!("exported policy bundle to {}", output.display()))
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_writes_manifest_and_embedded_sources() {
        let output = std::env::temp_dir().join(format!("lgtm-export-{}", std::process::id()));
        let message = run(&output, false).expect("export succeeds");
        assert!(message.contains("exported policy bundle"));
        assert!(output.join("manifest.json").is_file());
        assert!(output.join("rules.json").is_file());
        assert!(output.join("profiles/strict.json").is_file());
        assert_eq!(
            fs::read_to_string(output.join("rules.json")).expect("exported rules"),
            include_str!("../../policy/rules.json")
        );
        assert!(run(&output, false).is_err());
        fs::write(output.join("rules.json"), "modified\n").expect("modify export");
        run(&output, true).expect("force replaces modified export");
        assert_eq!(
            fs::read_to_string(output.join("rules.json")).expect("re-exported rules"),
            include_str!("../../policy/rules.json")
        );
        fs::remove_dir_all(output).ok();
    }
}
