//! Deterministic policy selection from task context.

use crate::context::TaskContext;
use crate::policy::{ChangeType, Rule};

/// Select rules whose scope and activation both match the task.
pub fn select_rules<'a>(
    context: &TaskContext,
    rules: &'a [Rule],
    change_type: ChangeType,
) -> Vec<&'a Rule> {
    let mut selected: Vec<_> = rules
        .iter()
        .filter(|rule| rule_matches(rule, context, change_type))
        .collect();
    selected.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    selected
}

fn rule_matches(rule: &Rule, context: &TaskContext, change_type: ChangeType) -> bool {
    matches_values(&rule.applies_to.languages, &context.languages)
        && matches_values(&rule.applies_to.domains, &context.domains)
        && matches_files(&rule.applies_to.file_patterns, &context.files_touched)
        && matches_change_type(&rule.activation.change_types, change_type)
        && matches_values(&rule.activation.signals, &context.risk_signals)
}

fn matches_values(required: &[String], observed: &[String]) -> bool {
    required.is_empty()
        || required
            .iter()
            .any(|candidate| observed.contains(candidate))
}

fn matches_change_type(required: &[ChangeType], observed: ChangeType) -> bool {
    required.is_empty() || required.contains(&observed)
}

fn matches_files(patterns: &[String], files: &[String]) -> bool {
    patterns.is_empty()
        || patterns
            .iter()
            .any(|pattern| files.iter().any(|file| glob_matches(pattern, file)))
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    pattern
        .strip_prefix("**/")
        .is_some_and(|suffix| glob_matches_core(suffix, path))
        || glob_matches_core(pattern, path)
}

fn glob_matches_core(pattern: &str, path: &str) -> bool {
    let pattern = pattern.as_bytes();
    let path = path.as_bytes();
    let mut current = vec![false; path.len() + 1];
    current[0] = true;
    let mut index = 0;
    while index < pattern.len() {
        let is_globstar = pattern[index] == b'*' && pattern.get(index + 1) == Some(&b'*');
        if is_globstar {
            current = apply_star(&current, path, true);
            index += 2;
        } else if pattern[index] == b'*' {
            current = apply_star(&current, path, false);
            index += 1;
        } else {
            current = apply_character(&current, path, pattern[index]);
            index += 1;
        }
    }
    current[path.len()]
}

fn apply_star(previous: &[bool], path: &[u8], crosses_separator: bool) -> Vec<bool> {
    let mut next = previous.to_vec();
    for index in 1..=path.len() {
        if next[index - 1] && (crosses_separator || path[index - 1] != b'/') {
            next[index] = true;
        }
    }
    next
}

fn apply_character(previous: &[bool], path: &[u8], expected: u8) -> Vec<bool> {
    let mut next = vec![false; path.len() + 1];
    for index in 1..=path.len() {
        let matches = expected == b'?' && path[index - 1] != b'/' || expected == path[index - 1];
        next[index] = previous[index - 1] && matches;
    }
    next
}

#[cfg(test)]
mod tests;
