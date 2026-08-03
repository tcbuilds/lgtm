//! Export the exact embedded policy bundle for inspection and CI pinning.

use std::fs;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

fn artifacts() -> Vec<(&'static str, String)> {
    let mut artifacts = vec![
        ("rules.json", embedded_rules_json()),
        (
            "config-v2.schema.json",
            crate::config_v2::SCHEMA_JSON.to_string(),
        ),
        (
            "semgrep-python.yml",
            include_str!("../../policy/semgrep-python.yml").to_string(),
        ),
        (
            "profiles/default.json",
            include_str!("../../policy/profiles/default.json").to_string(),
        ),
        (
            "profiles/strict.json",
            include_str!("../../policy/profiles/strict.json").to_string(),
        ),
        (
            "profiles/prototype.json",
            include_str!("../../policy/profiles/prototype.json").to_string(),
        ),
        (
            "profiles/infrastructure.json",
            include_str!("../../policy/profiles/infrastructure.json").to_string(),
        ),
        ("examples.md", examples_markdown()),
    ];
    artifacts.extend(
        super::bundle_digest_sources().map(|(path, contents, _)| (path, contents.to_string())),
    );
    artifacts
}

fn embedded_rules_json() -> String {
    let rules = super::load_embedded_registry().expect("embedded policy registry must validate");
    serde_json::to_string_pretty(&rules).expect("embedded policy registry must serialize")
}

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
    for (relative, contents) in artifacts() {
        let path = temp.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create artifact parent ({error})"))?;
        }
        fs::write(&path, contents.as_bytes())
            .map_err(|error| format!("write {relative} ({error})"))?;
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

fn examples_markdown() -> String {
    let rules = super::load_embedded_registry().expect("embedded policy registry must validate");
    let mut markdown = String::from(
        "# LGTM Policy Examples\n\nGenerated from the embedded policy registry. Examples are guidance, not automated proof.\n\n",
    );
    for rule in rules {
        if rule.examples.is_empty() {
            continue;
        }
        markdown.push_str(&format!("## `{}` — {}\n\n", rule.id, rule.title));
        markdown.push_str(&format!("- Languages: {}\n", language_scope(&rule)));
        markdown.push_str(&format!(
            "- Limitations: {}\n\n",
            rule.limitations.join(" ")
        ));
        for example in rule.examples {
            markdown.push_str(&format!(
                "- [{}] {} (schematic: {})\n",
                example.language,
                example.text.replace('\n', " "),
                example.schematic
            ));
        }
        markdown.push('\n');
    }
    markdown
}

fn language_scope(rule: &super::Rule) -> String {
    if rule.applies_to.languages.is_empty() {
        "all".to_string()
    } else {
        rule.applies_to.languages.join(", ")
    }
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
        let _ = fs::remove_dir_all(&output);
        let message = run(&output, false).expect("export succeeds");
        assert!(message.contains("exported policy bundle"));
        assert!(output.join("manifest.json").is_file());
        assert!(output.join("rules.json").is_file());
        assert!(output.join("examples.md").is_file());
        assert!(
            fs::read_to_string(output.join("examples.md"))
                .expect("exported examples")
                .contains("LGTM Policy Examples")
        );
        assert!(output.join("profiles/strict.json").is_file());
        let exported_rules = fs::read_to_string(output.join("rules.json")).expect("exported rules");
        let rules: serde_json::Value = serde_json::from_str(&exported_rules).expect("rules JSON");
        assert_eq!(rules.as_array().expect("rule array").len(), 71);

        // Every source hashed by bundle_digest must be present in the export.
        let manifest_text =
            fs::read_to_string(output.join("manifest.json")).expect("exported manifest");
        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_text).expect("manifest JSON");
        let manifest_files = manifest["files"].as_array().expect("manifest files");
        for (path, contents, _) in crate::policy::bundle_digest_sources() {
            assert_eq!(
                fs::read_to_string(output.join(path)).expect("exported digest source"),
                contents,
                "exported source must preserve {path}"
            );
            assert!(
                manifest_files.iter().any(|file| {
                    file["path"] == path && file["sha256"] == digest(contents.as_bytes())
                }),
                "manifest must enumerate digest source {path}"
            );
        }
        assert_eq!(
            manifest["binary_version"],
            env!("CARGO_PKG_VERSION"),
            "manifest must expose the version hashed by bundle_digest"
        );

        assert!(run(&output, false).is_err());
        fs::write(output.join("rules.json"), "modified\n").expect("modify export");
        run(&output, true).expect("force replaces modified export");
        let reexported_rules =
            fs::read_to_string(output.join("rules.json")).expect("re-exported rules");
        let rules: serde_json::Value =
            serde_json::from_str(&reexported_rules).expect("re-exported rules JSON");
        assert_eq!(rules.as_array().expect("rule array").len(), 71);
        fs::remove_dir_all(output).ok();
    }
}
