//! Empty compatibility policy for older managed installations.
//!
//! LGTM no longer installs automatic command bans. Keep an empty policy file so
//! existing installation discovery can recognize an initialized repository.
//! Preserve an existing repository policy byte-for-byte; it does not authorize
//! LGTM to change the host agent's permissions.

use super::*;

/// Create an empty compatibility policy only when no nonblank file exists.
pub(super) fn render_defaults(
    path: &Path,
    notes: &mut Vec<String>,
) -> Result<(Option<Vec<u8>>, String), InitError> {
    if let Some(contents) = read_if_exists(path)?
        && !contents.trim().is_empty()
    {
        notes.push("preserved existing .lgtm/execpolicy.json".to_string());
        return Ok((None, contents));
    }
    let document = "{\n  \"prohibited_commands\": []\n}\n".to_string();
    notes.push(
        "created empty .lgtm/execpolicy.json compatibility data; no automatic command bans"
            .to_string(),
    );
    Ok((Some(document.as_bytes().to_vec()), document))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lgtm-execpolicy-defaults-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir creatable");
        dir
    }

    #[test]
    fn fresh_repo_gets_an_empty_compatibility_policy() {
        let dir = temp_dir("fresh");
        let mut notes = Vec::new();
        let (rendered, contents) =
            render_defaults(&dir.join("execpolicy.json"), &mut notes).expect("render succeeds");
        assert_eq!(rendered, Some(contents.as_bytes().to_vec()));
        let parsed: Value = serde_json::from_str(&contents).expect("valid policy JSON");
        assert_eq!(parsed, json!({"prohibited_commands": []}));
        assert!(
            notes
                .iter()
                .any(|note| note.contains("no automatic command bans"))
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn existing_policy_is_preserved_byte_for_byte() {
        let dir = temp_dir("existing");
        let path = dir.join("execpolicy.json");
        let authored = "{\"prohibited_commands\":[[\"terraform\",\"destroy\"]]}\n";
        std::fs::write(&path, authored).expect("fixture writable");
        let mut notes = Vec::new();
        let (rendered, contents) = render_defaults(&path, &mut notes).expect("render succeeds");
        assert!(rendered.is_none());
        assert_eq!(contents, authored);
        assert!(notes.iter().any(|note| note.contains("preserved")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn blank_policy_is_treated_as_absent() {
        let dir = temp_dir("blank");
        let path = dir.join("execpolicy.json");
        std::fs::write(&path, "   \n").expect("fixture writable");
        let (rendered, contents) =
            render_defaults(&path, &mut Vec::new()).expect("render succeeds");
        assert!(rendered.is_some());
        assert_eq!(
            serde_json::from_str::<Value>(&contents).expect("valid policy JSON"),
            json!({"prohibited_commands": []})
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
