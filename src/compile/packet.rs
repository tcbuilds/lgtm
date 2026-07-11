use std::collections::BTreeSet;

use crate::policy::{Level, Rule};

use super::plan::{EnforcementPlan, build_plan};

pub(super) const MAX_RULES: usize = 256;
const MAX_LINE_BYTES: usize = 512;

/// Human instruction packet paired with its machine-readable plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledInstructions {
    pub packet: String,
    pub plan: EnforcementPlan,
}

/// Compile selected rules into compact human and machine representations.
pub fn compile_selected(rules: &[&Rule], touched_files: &[String]) -> CompiledInstructions {
    let rules = sorted_rules(rules);
    let plan = build_plan(&rules, touched_files);
    let packet = render_packet(&rules, &plan);
    CompiledInstructions { packet, plan }
}

fn sorted_rules<'a>(rules: &[&'a Rule]) -> Vec<&'a Rule> {
    let mut sorted: Vec<_> = rules.to_vec();
    sorted.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    sorted.dedup_by(|left, right| left.id == right.id);
    sorted.truncate(MAX_RULES);
    sorted
}

fn render_packet(rules: &[&Rule], plan: &EnforcementPlan) -> String {
    let must = instructions(rules, |level| level == Level::Must);
    let review = instructions(rules, |level| level != Level::Must);
    let mut packet = String::from("Applicable engineering constraints:\n\nMUST\n");
    append_lines(&mut packet, &must);
    packet.push_str("\nREVIEW\n");
    append_lines(&mut packet, &review);
    packet.push_str("\nVerification required:\n");
    append_prefixed(&mut packet, "check", &plan.checks);
    append_prefixed(&mut packet, "evidence", &plan.evidence_required);
    packet.push_str("\nDo not claim a check passed unless it was executed successfully.\n");
    packet
}

fn instructions(rules: &[&Rule], predicate: fn(Level) -> bool) -> Vec<String> {
    rules
        .iter()
        .filter(|rule| predicate(rule.level))
        .map(|rule| bounded_line(&rule.instruction))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn append_lines(packet: &mut String, lines: &[String]) {
    if lines.is_empty() {
        packet.push_str("- None\n");
    } else {
        for line in lines {
            packet.push_str("- ");
            packet.push_str(line);
            packet.push('\n');
        }
    }
}

fn append_prefixed(packet: &mut String, prefix: &str, lines: &[String]) {
    for line in lines {
        packet.push_str("- ");
        packet.push_str(prefix);
        packet.push_str(": ");
        packet.push_str(&bounded_line(line));
        packet.push('\n');
    }
}

fn bounded_line(value: &str) -> String {
    let clean = value.replace(['\n', '\r', '\t'], " ");
    let mut end = clean.len().min(MAX_LINE_BYTES);
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    clean[..end].to_string()
}
