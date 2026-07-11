use super::*;

/// Build the repository-local policy document for a detection result.
pub fn build_config(detection: &Detection) -> Value {
    let mut required = Map::new();
    for (language, commands) in &detection.required_commands {
        required.insert(language.clone(), json!(commands));
    }
    json!({
        "profile": "default",
        "languages": detection.languages,
        "disabled_rules": [],
        "severity_overrides": {},
        "required_commands": required,
    })
}

/// Merge the five lgtm hook entries into an existing settings object.
///
/// `existing` is the parsed settings object (an empty object for a fresh repo).
/// Existing hooks and unrelated top-level settings are preserved; lgtm entries
/// are appended only when a matching entry is not already present for that
/// event, making repeated merges idempotent. A pre-existing lgtm entry whose
/// matcher no longer matches the expected wiring is corrected in place rather
/// than skipped or duplicated. Returns the merged object.
///
/// Callers must have validated the shape of `existing` (via
/// [`validate_settings`]) before calling: a non-object `hooks` value or a
/// non-array event value is treated as empty here, but the boundary rejects
/// those inputs before any write so a malformed file is never silently
/// replaced.
pub fn merge_settings(existing: &Map<String, Value>) -> Map<String, Value> {
    let mut merged = existing.clone();

    let hooks_entry = merged
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(hooks) = hooks_entry else {
        let mut replacement = Map::new();
        insert_hook_events(&mut replacement);
        merged.insert("hooks".to_string(), Value::Object(replacement));
        return merged;
    };

    insert_hook_events(hooks);
    merged
}

/// Add each lgtm hook entry to the hooks map, reconciling any existing lgtm
/// entry for the same event: if one is found with the wrong matcher, its matcher
/// is corrected; if found and already correct, it is left exactly as authored
/// (preserving a path-qualified command); if absent, the entry is appended.
fn insert_hook_events(hooks: &mut Map<String, Value>) {
    for wiring in &HOOK_EVENTS {
        let entries = hooks
            .entry(wiring.event.to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        let Value::Array(entries) = entries else {
            continue;
        };
        match entries
            .iter_mut()
            .find(|entry| entry_runs_command(entry, wiring.command))
        {
            Some(existing_entry) => reconcile_matcher(existing_entry, wiring),
            None => entries.push(hook_entry(wiring)),
        }
    }
}

/// Correct an existing lgtm hook entry's matcher to the wiring's expected value
/// without disturbing anything else about it.
///
/// The entry's command (which may be a path-qualified binary) and nested hook
/// objects are left untouched; only the top-level `matcher` key is reconciled.
/// For a wiring that expects a matcher, the key is set when missing or wrong;
/// for a wiring with no matcher, a stray `matcher` key is removed. This keeps
/// re-init from clobbering a hand-adjusted command while still enforcing the
/// tool matcher the runtime depends on.
fn reconcile_matcher(entry: &mut Value, wiring: &HookWiring) {
    let Value::Object(object) = entry else {
        return;
    };
    match wiring.matcher {
        Some(matcher) => {
            let expected = Value::String(matcher.to_string());
            if object.get("matcher") != Some(&expected) {
                object.insert("matcher".to_string(), expected);
            }
        }
        None => {
            object.remove("matcher");
        }
    }
}

/// Build a single Claude Code hook entry for a wiring.
fn hook_entry(wiring: &HookWiring) -> Value {
    let inner = json!({
        "type": "command",
        "command": wiring.command,
    });
    match wiring.matcher {
        Some(matcher) => json!({ "matcher": matcher, "hooks": [inner] }),
        None => json!({ "hooks": [inner] }),
    }
}

/// True when a hook entry contains a nested command that runs `command`.
///
/// Inspects the entry's `hooks` array for a `command`-typed object whose
/// `command` invokes the wiring's subcommand, which is how Claude Code nests the
/// executable under each event entry. A hook whose `type` is not `command` is
/// ignored even if its `command` string matches, so a non-command hook that
/// happens to carry the same string never suppresses adding the required
/// executable hook. Matching tolerates a path-qualified binary: an existing
/// command such as `/usr/local/bin/lgtm hook stop` is recognized as the same
/// lgtm hook as the bare `lgtm hook stop` wiring.
pub(super) fn entry_runs_command(entry: &Value, command: &str) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|inner| {
            inner.iter().any(|hook| {
                hook.get("type").and_then(Value::as_str) == Some("command")
                    && hook
                        .get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|found| commands_match(found, command))
            })
        })
}

/// True when `found` is the same lgtm hook invocation as the expected wiring
/// `command`, tolerating a path-qualified binary.
///
/// The expected form is `lgtm <args>`; a found command matches when it is
/// exactly that, or when it ends with `/<expected>` (a path-qualified binary
/// such as `./bin/lgtm <args>` or `/usr/bin/lgtm <args>`).
pub(super) fn commands_match(found: &str, expected: &str) -> bool {
    if found == expected {
        return true;
    }
    let Some(suffix) = expected.strip_prefix("lgtm ") else {
        return false;
    };
    found.rsplit_once("lgtm ").is_some_and(|(prefix, rest)| {
        rest == suffix && (prefix.is_empty() || prefix.ends_with('/'))
    })
}
