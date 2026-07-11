use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::policy::Rule;

pub const ENFORCEMENT_PLAN_SCHEMA_JSON: &str =
    include_str!("../../schemas/enforcement-plan.schema.json");

/// Deterministic machine-readable plan compiled from selected rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPlan {
    pub context_identity: String,
    pub rule_ids: Vec<String>,
    pub checks: Vec<String>,
    pub evidence_required: Vec<String>,
}

pub(super) fn build_plan(rules: &[&Rule], touched_files: &[String]) -> EnforcementPlan {
    EnforcementPlan {
        context_identity: context_identity(touched_files),
        rule_ids: collect_values(rules, |rule| std::slice::from_ref(&rule.id)),
        checks: collect_values(rules, |rule| &rule.enforcement.checks),
        evidence_required: collect_values(rules, |rule| &rule.evidence.required),
    }
}

fn collect_values(rules: &[&Rule], values: fn(&Rule) -> &[String]) -> Vec<String> {
    rules
        .iter()
        .flat_map(|rule| values(rule).iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn context_identity(files: &[String]) -> String {
    let files: BTreeSet<_> = files.iter().take(1_024).collect();
    let mut hash = 0xcbf29ce484222325_u64;
    for file in files {
        for byte in file.as_bytes().iter().take(4_096) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("files-fnv1a64-{hash:016x}")
}
