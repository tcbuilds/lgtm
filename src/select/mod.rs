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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SelectionDecision {
    pub rule_id: String,
    pub selected: bool,
    pub reason: String,
}

pub fn explain_rules(
    context: &TaskContext,
    rules: &[Rule],
    change_type: ChangeType,
) -> Vec<SelectionDecision> {
    let mut decisions: Vec<_> = rules
        .iter()
        .map(|rule| SelectionDecision {
            rule_id: rule.id.clone(),
            selected: rule_matches(rule, context, change_type),
            reason: selection_reason(rule, context, change_type),
        })
        .collect();
    decisions.sort_unstable_by(|left, right| left.rule_id.cmp(&right.rule_id));
    decisions
}

fn selection_reason(rule: &Rule, context: &TaskContext, change_type: ChangeType) -> String {
    if !matches_values(&rule.applies_to.languages, &context.languages) {
        return "language scope did not match".to_string();
    }
    if !matches_values(&rule.applies_to.domains, &context.domains) {
        return "domain scope did not match".to_string();
    }
    if !matches_files(&rule.applies_to.file_patterns, &context.files_touched) {
        return "file pattern did not match".to_string();
    }
    if !matches_change_type(&rule.activation.change_types, change_type) {
        return "change type did not match".to_string();
    }
    if !matches_values(&rule.activation.signals, &context.risk_signals) {
        return "activation signal did not match".to_string();
    }
    "all scope and activation conditions matched".to_string()
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
            .any(|pattern| files.iter().any(|file| file_pattern_matches(pattern, file)))
}

/// Match one repository-relative path against the selector's supported glob syntax.
pub fn file_pattern_matches(pattern: &str, path: &str) -> bool {
    glob_matches(pattern, path)
}

/// Report whether a file pattern uses syntax implemented by the production matcher.
pub fn file_pattern_is_supported(pattern: &str) -> bool {
    let mut brace_depth = 0_u32;
    for byte in pattern.bytes() {
        match byte {
            b'{' => brace_depth += 1,
            b'}' if brace_depth > 0 => brace_depth -= 1,
            b'}' | b'[' | b']' => return false,
            _ => {}
        }
    }
    brace_depth == 0
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    if !file_pattern_is_supported(pattern) {
        return false;
    }
    GlobNfa::compile(pattern).is_some_and(|automaton| automaton.matches(path))
}

#[derive(Debug)]
enum Transition {
    Epsilon(usize),
    Literal {
        next: usize,
        byte: u8,
    },
    Wildcard {
        next: usize,
        crosses_separator: bool,
    },
}

#[derive(Debug)]
struct GlobNfa {
    transitions: Vec<Vec<Transition>>,
    start: usize,
    accept: usize,
}

impl GlobNfa {
    fn compile(pattern: &str) -> Option<Self> {
        let mut automaton = Self {
            transitions: Vec::new(),
            start: 0,
            accept: 0,
        };
        let start = automaton.new_state();
        let mut index = 0;
        let accept = automaton.compile_sequence(pattern.as_bytes(), &mut index, start, false)?;
        if index != pattern.len() {
            return None;
        }
        automaton.start = start;
        automaton.accept = accept;
        Some(automaton)
    }

    fn new_state(&mut self) -> usize {
        let state = self.transitions.len();
        self.transitions.push(Vec::new());
        state
    }

    fn add_epsilon(&mut self, from: usize, next: usize) {
        self.transitions[from].push(Transition::Epsilon(next));
    }

    fn add_literal(&mut self, from: usize, next: usize, byte: u8) {
        self.transitions[from].push(Transition::Literal { next, byte });
    }

    fn add_wildcard(&mut self, from: usize, next: usize, crosses_separator: bool) {
        self.transitions[from].push(Transition::Wildcard {
            next,
            crosses_separator,
        });
    }

    fn compile_sequence(
        &mut self,
        pattern: &[u8],
        index: &mut usize,
        start: usize,
        stop_at_comma: bool,
    ) -> Option<usize> {
        let mut current = start;
        while *index < pattern.len() {
            match pattern[*index] {
                b'}' => break,
                b',' if stop_at_comma => break,
                b'{' => {
                    *index += 1;
                    let after = self.new_state();
                    loop {
                        let branch_end = self.compile_sequence(pattern, index, current, true)?;
                        self.add_epsilon(branch_end, after);
                        match pattern.get(*index) {
                            Some(b',') => *index += 1,
                            Some(b'}') => {
                                *index += 1;
                                break;
                            }
                            _ => return None,
                        }
                    }
                    current = after;
                }
                b'*' if pattern.get(*index + 1) == Some(&b'*') => {
                    if pattern.get(*index + 2) == Some(&b'/') {
                        let after = self.new_state();
                        self.add_epsilon(current, after);
                        self.add_wildcard(current, current, true);
                        self.add_literal(current, after, b'/');
                        *index += 3;
                        current = after;
                    } else {
                        let after = self.new_state();
                        self.add_epsilon(current, after);
                        self.add_wildcard(current, current, true);
                        *index += 2;
                        current = after;
                    }
                }
                b'*' => {
                    let after = self.new_state();
                    self.add_epsilon(current, after);
                    self.add_wildcard(current, current, false);
                    *index += 1;
                    current = after;
                }
                b'?' => {
                    let next = self.new_state();
                    self.add_wildcard(current, next, false);
                    *index += 1;
                    current = next;
                }
                byte => {
                    let next = self.new_state();
                    self.add_literal(current, next, byte);
                    *index += 1;
                    current = next;
                }
            }
        }
        Some(current)
    }

    fn matches(&self, path: &str) -> bool {
        let mut active = vec![false; self.transitions.len()];
        active[self.start] = true;
        self.epsilon_closure(&mut active);

        for byte in path.bytes() {
            let mut next = vec![false; self.transitions.len()];
            for (state, transitions) in self.transitions.iter().enumerate() {
                if !active[state] {
                    continue;
                }
                for transition in transitions {
                    match transition {
                        Transition::Literal {
                            next: destination,
                            byte: expected,
                        } if *expected == byte => next[*destination] = true,
                        Transition::Wildcard {
                            next: destination,
                            crosses_separator,
                        } if *crosses_separator || byte != b'/' => next[*destination] = true,
                        _ => {}
                    }
                }
            }
            self.epsilon_closure(&mut next);
            active = next;
        }
        active[self.accept]
    }

    fn epsilon_closure(&self, active: &mut [bool]) {
        let mut pending: Vec<_> = active
            .iter()
            .enumerate()
            .filter_map(|(state, is_active)| is_active.then_some(state))
            .collect();
        while let Some(state) = pending.pop() {
            for transition in &self.transitions[state] {
                let Transition::Epsilon(next) = transition else {
                    continue;
                };
                if !active[*next] {
                    active[*next] = true;
                    pending.push(*next);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
