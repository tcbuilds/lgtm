//! Default destructive-command policy seeded by `lgtm init`.
//!
//! `lgtm init` writes `.lgtm/execpolicy.json` when the file is absent so a fresh
//! repository has hard-stop coverage for irreversible shell commands instead of
//! an empty policy. An existing file is never rewritten, reordered, or merged
//! into: it is preserved verbatim, matching how [`super::config::render_config`]
//! treats a user-edited `.lgtm/config.json`.

use super::*;

/// Destructive argv prefixes seeded into a fresh `.lgtm/execpolicy.json`.
///
/// [`crate::hooks::pre_tool_use`] matches these as argv *prefixes*
/// (`argv.starts_with(prefix)`), so each entry blocks the exact leading tokens
/// and nothing else. The list is deliberately narrow: every entry names an
/// operation that destroys data or history irrecoverably, because a false block
/// on a legitimate command costs more than the marginal coverage a broader
/// pattern would buy.
///
/// Two exclusions are deliberate. `git push --force-with-lease` is absent
/// because it refuses to overwrite commits the pusher has not seen, which makes
/// it the safe alternative an agent should reach for once `--force` is denied.
/// Bare `git clean -fd` is absent because it leaves gitignored files (including
/// local `.env` files) alone; only the `-x` forms that also delete ignored files
/// are blocked.
const DEFAULT_PROHIBITED_COMMANDS: &[&[&str]] = &[
    &["rm", "-rf"],
    &["rm", "-fr"],
    &["rm", "-Rf"],
    &["rm", "-fR"],
    &["git", "push", "--force"],
    &["git", "push", "-f"],
    &["git", "reset", "--hard"],
    &["git", "clean", "-fdx"],
    &["git", "clean", "-xdf"],
    &["dd"],
    &["mkfs"],
    &["chmod", "-R", "777"],
    &["shred"],
];

/// Render the desired `.lgtm/execpolicy.json` bytes, or `None` when a policy
/// already exists.
///
/// Returns the bytes to write alongside the contents that will be on disk once
/// this init completes, so the Codex rules compiler can consume a policy created
/// in the same run rather than only seeing it on a second init. A file that
/// exists but is blank is treated as absent and seeded.
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
    let document = default_document();
    notes.push(
        "seeded .lgtm/execpolicy.json with default destructive-command prefixes; edit it to suit this repository"
            .to_string(),
    );
    Ok((Some(document.clone().into_bytes()), document))
}

/// Serialize [`DEFAULT_PROHIBITED_COMMANDS`] into the on-disk policy document.
///
/// Each argv prefix is emitted on a single line rather than through
/// `to_string_pretty`, which would put every argv item on its own line and turn
/// a thirteen-rule policy into sixty lines nobody wants to hand-edit. The result
/// is still ordinary JSON.
fn default_document() -> String {
    let rules: Vec<String> = DEFAULT_PROHIBITED_COMMANDS
        .iter()
        .map(|prefix| {
            let encoded =
                serde_json::to_string(prefix).expect("a list of string literals always serializes");
            format!("    {encoded}")
        })
        .collect();
    format!(
        "{{\n  \"prohibited_commands\": [\n{}\n  ]\n}}\n",
        rules.join(",\n")
    )
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
    fn fresh_repo_gets_the_default_destructive_prefixes() {
        let dir = temp_dir("fresh");
        let path = dir.join("execpolicy.json");
        let mut notes = Vec::new();

        let (rendered, contents) = render_defaults(&path, &mut notes).expect("render must succeed");
        let bytes = rendered.expect("an absent policy must be seeded");
        assert_eq!(String::from_utf8(bytes).expect("UTF-8 policy"), contents);

        let parsed: Value = serde_json::from_str(&contents).expect("default policy is valid JSON");
        let commands = parsed["prohibited_commands"]
            .as_array()
            .expect("prohibited_commands array");
        assert!(commands.contains(&json!(["rm", "-rf"])));
        assert!(commands.contains(&json!(["git", "push", "--force"])));
        assert!(commands.contains(&json!(["git", "reset", "--hard"])));
        assert!(
            !commands.contains(&json!(["git", "push", "--force-with-lease"])),
            "the safe lease-checked force push must stay allowed"
        );
        assert!(
            !commands.contains(&json!(["git", "clean", "-fd"])),
            "cleaning untracked-but-not-ignored files must stay allowed"
        );
        assert!(notes.iter().any(|note| note.contains("seeded")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn existing_policy_is_preserved_byte_for_byte() {
        let dir = temp_dir("existing");
        let path = dir.join("execpolicy.json");
        let authored = "{\"prohibited_commands\":[[\"terraform\",\"destroy\"]]}\n";
        std::fs::write(&path, authored).expect("fixture writable");
        let mut notes = Vec::new();

        let (rendered, contents) = render_defaults(&path, &mut notes).expect("render must succeed");
        assert!(
            rendered.is_none(),
            "an existing policy must never be rewritten or reordered"
        );
        assert_eq!(contents, authored);
        assert!(notes.iter().any(|note| note.contains("preserved")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blank_policy_is_treated_as_absent_and_seeded() {
        let dir = temp_dir("blank");
        let path = dir.join("execpolicy.json");
        std::fs::write(&path, "   \n").expect("fixture writable");
        let mut notes = Vec::new();

        let (rendered, _) = render_defaults(&path, &mut notes).expect("render must succeed");
        assert!(rendered.is_some(), "a blank policy must be seeded");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_default_prefix_is_a_non_empty_argv_list() {
        for prefix in DEFAULT_PROHIBITED_COMMANDS {
            assert!(
                !prefix.is_empty(),
                "an empty prefix would match every command"
            );
            assert!(
                prefix.iter().all(|item| !item.is_empty()),
                "{prefix:?} contains an empty argv item"
            );
        }
    }
}
