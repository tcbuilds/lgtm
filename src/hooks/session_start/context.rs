use crate::detect::Detection;

use super::config::{Config, ConfigState};

const ALLOWED_PROFILES: [&str; 4] = ["default", "strict", "prototype", "infrastructure"];
const ALLOWED_SOURCES: [&str; 4] = ["startup", "resume", "clear", "compact"];
const MAX_VALUE_CHARS: usize = 200;
const MAX_LIST_ITEMS: usize = 16;
pub(super) const MAX_CONTEXT_BYTES: usize = 16 * 1024;
pub(super) const TRUNCATION_MARKER: &str = "\n… (context truncated)";

pub(super) fn build_context(
    detection: &Detection,
    config: &ConfigState,
    source: Option<&str>,
) -> String {
    let mut lines = invariant_lines();
    append_source(&mut lines, source);
    append_status(&mut lines, detection, config);
    truncate_context(lines.join("\n"))
}

fn invariant_lines() -> Vec<String> {
    [
        "lgtm engineering harness — active.",
        "- The harness is authoritative.",
        "- Hook failures must be fixed, not bypassed.",
        "- Verification claims require evidence; do not claim a check passed unless it ran.",
        "- Repository-local conventions take precedence unless they violate a MUST rule.",
        "- Do not bypass or edit harness files unless the task explicitly concerns the harness.",
    ]
    .map(str::to_string)
    .to_vec()
}

fn append_source(lines: &mut Vec<String>, source: Option<&str>) {
    if let Some(source) = source
        && ALLOWED_SOURCES.contains(&source)
    {
        lines.push(format!("Session source: {source}."));
    }
}

fn append_status(lines: &mut Vec<String>, detection: &Detection, config: &ConfigState) {
    match config {
        ConfigState::NotInitialized => append_uninitialized(lines, detection),
        ConfigState::Malformed(reason) => append_malformed(lines, detection, reason),
        ConfigState::Present(config) => append_present(lines, detection, config),
    }
}

fn append_uninitialized(lines: &mut Vec<String>, detection: &Detection) {
    lines.push("lgtm is not initialized in this repository (no .lgtm/config.json). Run `lgtm init` to enable enforcement.".to_string());
    append_detected_languages(lines, detection);
}

fn append_malformed(lines: &mut Vec<String>, detection: &Detection, reason: &str) {
    lines.push(format!(
        "config malformed ({reason}), fix .lgtm/config.json."
    ));
    append_detected_languages(lines, detection);
}

fn append_present(lines: &mut Vec<String>, detection: &Detection, config: &Config) {
    lines.push(profile_line(&config.profile));
    append_detected_languages(lines, detection);
    lines.push(config_languages_line(config));
    lines.push(commands_summary(detection));
}

fn append_detected_languages(lines: &mut Vec<String>, detection: &Detection) {
    lines.push(format!(
        "Detected languages: {}.",
        languages_summary(detection)
    ));
}

pub(super) fn truncate_context(context: String) -> String {
    if context.len() <= MAX_CONTEXT_BYTES {
        return context;
    }
    let budget = MAX_CONTEXT_BYTES - TRUNCATION_MARKER.len();
    let mut cut = budget.min(context.len());
    while cut > 0 && !context.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut truncated = context;
    truncated.truncate(cut);
    truncated.push_str(TRUNCATION_MARKER);
    truncated
}

fn profile_line(profile: &str) -> String {
    if ALLOWED_PROFILES.contains(&profile) {
        return format!("Profile: {profile}.");
    }
    format!(
        "Profile: default (unknown profile '{}', treating as default).",
        sanitize_value(profile)
    )
}

fn sanitize_value(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_VALUE_CHARS)
        .collect()
}

fn languages_summary(detection: &Detection) -> String {
    if detection.languages.is_empty() {
        "none".to_string()
    } else {
        detection.languages.join(", ")
    }
}

fn cap_list(items: Vec<String>) -> Vec<String> {
    if items.len() <= MAX_LIST_ITEMS {
        return items;
    }
    let mut capped: Vec<String> = items.into_iter().take(MAX_LIST_ITEMS).collect();
    capped.push("…".to_string());
    capped
}

fn config_languages_line(config: &Config) -> String {
    if config.languages.is_empty() {
        return "Configured languages: none.".to_string();
    }
    let sanitized = config
        .languages
        .iter()
        .map(|language| sanitize_value(language))
        .collect();
    format!("Configured languages: {}.", cap_list(sanitized).join(", "))
}

fn commands_summary(detection: &Detection) -> String {
    let commands = detection
        .required_commands
        .iter()
        .flat_map(|(_, commands)| commands.iter())
        .map(|command| sanitize_value(command))
        .collect();
    let commands = cap_list(commands);
    if commands.is_empty() {
        "Required commands: none detected.".to_string()
    } else {
        format!("Required commands: {}.", commands.join("; "))
    }
}
