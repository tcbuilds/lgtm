use super::*;
use crate::policy::{Level, load_embedded_registry};

#[test]
fn compiles_compact_deduplicated_packet_in_stable_order() {
    let registry = load_embedded_registry().expect("registry valid");
    let mut review = registry[0].clone();
    review.id = "review-fixture".to_string();
    review.level = Level::Review;
    review.instruction = "Review the boundary design.".to_string();
    let selected = vec![&review, &registry[2], &registry[2], &registry[1]];

    let compiled = compile_selected(
        &selected,
        &["src/api.py".to_string(), "tests/test_api.py".to_string()],
    );

    assert!(
        compiled
            .packet
            .starts_with("Applicable engineering constraints:")
    );
    assert!(compiled.packet.contains("\nMUST\n"));
    assert!(
        compiled
            .packet
            .contains("\nREVIEW\n- Review the boundary design.")
    );
    assert!(compiled.packet.contains("Verification required:"));
    assert!(compiled.packet.contains("Do not claim a check passed"));
    assert!(!compiled.packet.contains("codingStandards.md"));
    assert!(compiled.packet.len() < 4_096, "packet must remain compact");
    assert_eq!(
        compiled.plan.rule_ids,
        [
            "no-broad-exception-handling",
            "no-swallowed-errors",
            "review-fixture"
        ]
    );
}

#[test]
fn plan_identity_tracks_touched_file_set_not_input_order() {
    let registry = load_embedded_registry().expect("registry valid");
    let selected = vec![&registry[2]];
    let first = compile_selected(&selected, &["b.py".to_string(), "a.py".to_string()]);
    let reordered = compile_selected(&selected, &["a.py".to_string(), "b.py".to_string()]);
    let changed = compile_selected(&selected, &["a.py".to_string()]);

    assert_eq!(first.plan.context_identity, reordered.plan.context_identity);
    assert_ne!(first.plan.context_identity, changed.plan.context_identity);
}

#[test]
fn rule_cap_is_independent_of_input_order() {
    let registry = load_embedded_registry().expect("registry valid");
    let source = registry.first().expect("seed rule");
    let mut rules: Vec<_> = (0..300)
        .map(|index| {
            let mut rule = source.clone();
            rule.id = format!("rule-{index:03}");
            rule
        })
        .collect();
    let forward_refs: Vec<_> = rules.iter().collect();
    let forward = compile_selected(&forward_refs, &[]);
    rules.reverse();
    let reverse_refs: Vec<_> = rules.iter().collect();
    let reverse = compile_selected(&reverse_refs, &[]);

    assert_eq!(forward, reverse);
    assert_eq!(forward.plan.rule_ids.len(), super::packet::MAX_RULES);
    assert_eq!(
        forward.plan.rule_ids.first().map(String::as_str),
        Some("rule-000")
    );
    assert_eq!(
        forward.plan.rule_ids.last().map(String::as_str),
        Some("rule-255")
    );
}

#[test]
fn real_emitted_plan_validates_against_schema() {
    let registry = load_embedded_registry().expect("registry valid");
    let selected: Vec<_> = registry.iter().collect();
    let compiled = compile_selected(&selected, &["src/routes/events.py".to_string()]);
    let schema: serde_json::Value =
        serde_json::from_str(ENFORCEMENT_PLAN_SCHEMA_JSON).expect("schema JSON valid");
    let artifact = serde_json::to_value(&compiled.plan).expect("plan serializable");
    let validator = jsonschema::validator_for(&schema).expect("schema valid");

    let errors: Vec<_> = validator
        .iter_errors(&artifact)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "plan schema violations: {errors:?}");
}
