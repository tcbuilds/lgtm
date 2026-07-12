use super::*;

pub(super) fn render_gitignore(
    path: &Path,
    notes: &mut Vec<String>,
) -> Result<Option<Vec<u8>>, InitError> {
    let existing = read_if_exists(path)?;

    match existing {
        Some(contents) if evidence_is_ignored(&contents) => {
            if contents
                .lines()
                .any(|line| line.trim() == "!**/.lgtm/evidence/")
            {
                notes.push(
                    "contradictory .gitignore negation re-includes .lgtm/evidence/; remove it"
                        .to_string(),
                );
            }
            if !gitignore_has_explicit_evidence_rule(&contents) {
                notes.push(
                    ".gitignore ignores .lgtm/ wholesale; .lgtm/config.json will be untracked"
                        .to_string(),
                );
            }
            Ok(None)
        }
        Some(contents) => {
            if contents
                .lines()
                .any(|line| line.trim() == "!**/.lgtm/evidence/")
            {
                notes.push(
                    "contradictory .gitignore negation re-includes .lgtm/evidence/; remove it"
                        .to_string(),
                );
            }
            let newline = if contents.contains("\r\n") {
                "\r\n"
            } else {
                "\n"
            };
            let mut updated = contents;
            if !updated.is_empty() && !updated.ends_with('\n') {
                updated.push_str(newline);
            }
            updated.push_str(EVIDENCE_GITIGNORE_LINE);
            updated.push_str(newline);
            Ok(Some(updated.into_bytes()))
        }
        None => {
            let contents = format!("{EVIDENCE_GITIGNORE_LINE}\n");
            Ok(Some(contents.into_bytes()))
        }
    }
}

/// True when `.lgtm/evidence/` is ignored after applying every matching rule in
/// order, honoring negation.
///
/// Evaluates the file with gitignore last-matching-rule semantics restricted to
/// the `.lgtm/evidence/` path: each line either ignores or (with a leading `!`)
/// re-includes the path, and the final matching rule wins. A wholesale `.lgtm/`
/// rule matches the evidence path, but a later `!.lgtm/evidence/` negation flips
/// the outcome back to "not ignored" — in which case init must still append its
/// explicit rule. Returns `false` when no rule matches the evidence path.
pub(super) fn evidence_is_ignored(contents: &str) -> bool {
    let mut ignored = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (negated, pattern) = match trimmed.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, trimmed),
        };
        if gitignore_pattern_matches_evidence(pattern) {
            ignored = !negated;
        }
    }
    ignored
}

/// True when a gitignore pattern (already stripped of a leading `!`) matches the
/// `.lgtm/evidence/` path, either directly or via a wholesale `.lgtm/` rule.
///
/// Trailing slashes are tolerated so `.lgtm`, `.lgtm/`, `.lgtm/evidence`, and
/// `.lgtm/evidence/` are all recognized.
fn gitignore_pattern_matches_evidence(pattern: &str) -> bool {
    let normalized = pattern.trim_end_matches('/');
    normalized == ".lgtm" || normalized == ".lgtm/evidence" || normalized == "**/.lgtm/evidence"
}

/// True when the file carries an explicit, non-negated evidence rule (as opposed
/// to only matching via a wholesale `.lgtm/` rule), so the untracked-config note
/// is suppressed when the evidence directory is ignored by its own line.
fn gitignore_has_explicit_evidence_rule(contents: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == EVIDENCE_GITIGNORE_LINE
            || trimmed == ".lgtm/evidence"
            || trimmed == "**/.lgtm/evidence"
    })
}

/// Render the merged `.claude/settings.json` bytes from a pre-validated object,
/// or `None` when the merge leaves the settings unchanged.
///
/// `validated` is the result of [`validate_settings`]: `None` for a fresh repo,
/// or the parsed object when one already exists. Returns `None` when the merge
/// does not change the object, keeping repeated runs idempotent; the caller is
/// responsible for creating the parent `.claude/` directory before staging.
pub(super) fn render_settings(validated: ValidatedSettings) -> Option<Vec<u8>> {
    let existing_object = validated.unwrap_or_default();
    let merged = merge_settings(&existing_object);
    if merged == existing_object {
        return None;
    }

    let mut serialized = serde_json::to_string_pretty(&Value::Object(merged))
        .expect("settings map serializes as a JSON object");
    serialized.push('\n');
    Some(serialized.into_bytes())
}
