//! Codex project-hook configuration merge.

use super::config::ValidatedSettings;
use super::settings::commands_match;
use serde_json::{Map, Value, json};

const CODEX_HOOKS: [HookWiring; 5] = [
    HookWiring {
        event: "SessionStart",
        command: "lgtm hook session-start --adapter codex",
        matcher: None,
    },
    HookWiring {
        event: "UserPromptSubmit",
        command: "lgtm hook user-prompt-submit --adapter codex",
        matcher: None,
    },
    HookWiring {
        event: "PreToolUse",
        command: "lgtm hook pre-tool-use --adapter codex",
        matcher: Some("apply_patch|Edit|Write|exec_command|unified_exec|Bash"),
    },
    HookWiring {
        event: "PostToolUse",
        command: "lgtm hook post-tool-use --adapter codex",
        matcher: Some("apply_patch|Edit|Write|exec_command|unified_exec|Bash"),
    },
    HookWiring {
        event: "Stop",
        command: "lgtm hook stop --adapter codex",
        matcher: None,
    },
];

struct HookWiring {
    event: &'static str,
    command: &'static str,
    matcher: Option<&'static str>,
}

pub(super) fn render_hooks(validated: ValidatedSettings) -> Option<Vec<u8>> {
    let existing = validated.unwrap_or_default();
    let merged = merge_hooks(&existing);
    if merged == existing {
        return None;
    }
    let mut serialized = serde_json::to_string_pretty(&Value::Object(merged))
        .expect("Codex hooks map serializes as a JSON object");
    serialized.push('\n');
    Some(serialized.into_bytes())
}

pub(super) fn merge_hooks(existing: &Map<String, Value>) -> Map<String, Value> {
    let mut merged = existing.clone();
    let hooks_entry = merged
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(hooks) = hooks_entry else {
        return merged;
    };
    for wiring in &CODEX_HOOKS {
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
            Some(entry) => reconcile_matcher(entry, wiring.matcher),
            None => entries.push(hook_entry(wiring)),
        }
    }
    merged
}

fn entry_runs_command(entry: &Value, expected: &str) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| {
            hooks.iter().any(|hook| {
                hook.get("type").and_then(Value::as_str) == Some("command")
                    && hook
                        .get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|found| commands_match(found, expected))
            })
        })
}

fn reconcile_matcher(entry: &mut Value, matcher: Option<&str>) {
    let Value::Object(entry) = entry else {
        return;
    };
    match matcher {
        Some(matcher) => {
            entry.insert("matcher".to_string(), Value::String(matcher.to_string()));
        }
        None => {
            entry.remove("matcher");
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_adds_all_codex_events_and_matchers() {
        let merged = merge_hooks(&Map::new());
        let hooks = merged["hooks"].as_object().expect("hooks object");
        assert_eq!(hooks.len(), 5);
        assert_eq!(
            hooks["PreToolUse"][0]["matcher"],
            "apply_patch|Edit|Write|exec_command|unified_exec|Bash"
        );
        assert_eq!(
            hooks["PreToolUse"][0]["hooks"][0]["command"],
            "lgtm hook pre-tool-use --adapter codex"
        );
    }

    #[test]
    fn merge_is_idempotent_and_preserves_unrelated_values() {
        let existing = json!({
            "permissions": {"allow": ["Bash"]},
            "hooks": {
                "Stop": [{"hooks": [{"type": "command", "command": "other"}]}]
            }
        });
        let existing = existing.as_object().expect("object").clone();
        let once = merge_hooks(&existing);
        let twice = merge_hooks(&once);
        assert_eq!(once, twice);
        assert_eq!(once["permissions"], json!({"allow": ["Bash"]}));
        assert_eq!(once["hooks"]["Stop"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn merge_reconciles_path_qualified_lgtm_matcher() {
        let existing = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": "/usr/local/bin/lgtm hook pre-tool-use --adapter codex"
                    }]
                }]
            }
        });
        let merged = merge_hooks(existing.as_object().expect("object"));
        assert_eq!(
            merged["hooks"]["PreToolUse"][0]["matcher"],
            "apply_patch|Edit|Write|exec_command|unified_exec|Bash"
        );
        assert_eq!(merged["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }
}
