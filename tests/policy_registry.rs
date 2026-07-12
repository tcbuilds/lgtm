//! Integration tests for the embedded policy registry and its schema.

use lgtm::policy::{self, Category, EnforcementMode, Level, RegistryError, Rule, Severity};

/// The embedded registry validates against the embedded rule schema and
/// deserializes into the expected seed rules.
#[test]
fn embedded_registry_validates_against_schema() {
    let rules = policy::load_embedded_registry().expect("embedded registry must validate");
    let ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "no-committed-secrets",
            "no-swallowed-errors",
            "no-broad-exception-handling",
            "external-call-timeout",
            "public-input-validation",
            "sql-parameterization",
            "bounded-retries-loops",
            "destructive-operation-safeguards",
            "regression-test-required",
            "new-behavior-tests-required",
            "preserve-unrelated-user-changes",
            "new-dependency-review",
            "auth-change-security-review",
            "required-repository-commands",
            "evidence-claims-honest",
            "rust-no-unsafe",
            "rust-no-unwrap-expect",
            "typescript-no-any",
            "react-no-state-mutation",
            "react-unstable-key",
            "typescript-unsafe-unknown",
            "typescript-api-response-validation",
            "rust-spawn-cancellation",
            "rust-no-mutable-global",
            "react-effect-cleanup",
            "react-error-loading-states",
            "react-accessibility-review",
            "rust-async-timeout-review",
            "rust-id-unit-newtype-review",
            "go-ignored-error",
            "go-goroutine-cancellation",
            "go-mutable-global",
            "go-error-wrapping",
            "go-context-first-review",
            "function-size",
            "file-size",
            "function-complexity",
            "shell-safety-review",
            "shell-idempotency-review",
            "iac-validation-review",
            "config-schema-review",
            "public-endpoint-review",
            "safe-construction-review",
            "justification-metadata",
            "sql-migration-review",
            "cpp-review",
            "csharp-review",
            "jvm-review",
            "ui-accessibility-review",
            "ui-responsive-review",
            "test-naming-review",
            "determinism-review",
            "behavior-test-quality",
            "test-quality-guidance",
            "debugging-protocol",
            "sensitive-logging-review",
            "structured-observability-review",
            "boundary-error-review",
            "contextual-design-guidance",
            "naming-review",
            "module-boundary-review",
            "error-contract-review",
            "anti-slop-checklist",
        ]
    );
}

/// A rule fixture that violates the schema fails validation with a message that
/// names the offending rule index and the schema problem.
#[test]
fn malformed_rule_fails_with_useful_message() {
    let malformed = include_str!("fixtures/malformed_rule.json");
    let error =
        policy::load_and_validate(malformed).expect_err("malformed registry must be rejected");

    match error {
        RegistryError::SchemaViolations(messages) => {
            let joined = messages.join("\n");
            assert!(
                joined.contains("rule[0]"),
                "message must point at the offending rule index, got: {joined}"
            );
            assert!(
                joined.contains("enforcement"),
                "message must report the missing enforcement field, got: {joined}"
            );
            assert!(
                joined.contains("severity"),
                "message must report the invalid severity value, got: {joined}"
            );
        }
        other => panic!("expected schema violations, got {other:?}"),
    }
}

/// A registry with two rules sharing an `id` is rejected by the registry-wide
/// uniqueness check, with an error that names the duplicated id and both rule
/// indices.
#[test]
fn duplicate_rule_ids_are_rejected() {
    let duplicate = include_str!("fixtures/duplicate_rule_ids.json");
    let error =
        policy::load_and_validate(duplicate).expect_err("duplicate rule ids must be rejected");

    match error {
        RegistryError::DuplicateId {
            id,
            first_index,
            duplicate_index,
        } => {
            assert_eq!(id, "shared-id");
            assert_eq!(first_index, 0);
            assert_eq!(duplicate_index, 1);
        }
        other => panic!("expected a duplicate id error, got {other:?}"),
    }
}

#[test]
fn automated_capability_without_registered_check_is_rejected() {
    let invalid = include_str!("fixtures/invalid_capability.json");
    let error = policy::load_and_validate(invalid).expect_err("invalid capability must fail");
    assert!(matches!(error, RegistryError::CapabilityViolation { .. }));
}

/// A registry that is valid JSON but not a JSON array is rejected as a schema
/// violation naming the array requirement.
#[test]
fn non_array_registry_is_rejected() {
    let error = policy::load_and_validate("{}").expect_err("a non-array registry must be rejected");

    match error {
        RegistryError::SchemaViolations(messages) => {
            let joined = messages.join("\n");
            assert!(
                joined.contains("array"),
                "message must state the registry must be an array, got: {joined}"
            );
        }
        other => panic!("expected schema violations, got {other:?}"),
    }
}

/// A registry that is not valid JSON is rejected via the `RegistryJson` variant.
#[test]
fn non_json_registry_is_rejected() {
    let error =
        policy::load_and_validate("not json at all").expect_err("non-JSON input must be rejected");

    assert!(
        matches!(error, RegistryError::RegistryJson(_)),
        "non-JSON input must surface as a RegistryJson error, got {error:?}"
    );
}

/// The full external-call-timeout example round-trips through the struct model:
/// deserialized fields match the registry, and re-serializing then re-parsing
/// yields an identical rule.
#[test]
fn full_example_rule_round_trips() {
    let rules = policy::load_embedded_registry().expect("embedded registry must validate");
    let rule = rules
        .iter()
        .find(|rule| rule.id == "external-call-timeout")
        .expect("registry must contain the external-call-timeout rule");

    assert_eq!(rule.title, "External calls require timeouts");
    assert_eq!(rule.severity, Severity::Error);
    assert_eq!(rule.level, Level::Must);
    assert_eq!(rule.category, Category::Reliability);
    assert_eq!(rule.applies_to.languages, vec!["python".to_string()]);
    assert_eq!(rule.enforcement.mode, EnforcementMode::Static);
    assert_eq!(
        rule.enforcement.checks,
        vec!["semgrep.external-call-timeout".to_string()]
    );
    assert!(!rule.overridable);
    assert_eq!(
        rule.evidence.required,
        vec!["check_result".to_string(), "changed_locations".to_string()]
    );
    assert_eq!(
        rule.references,
        vec!["codingStandards.md#non-negotiable-rules".to_string()]
    );

    let serialized = serde_json::to_string(rule).expect("rule must serialize");
    let reparsed: Rule = serde_json::from_str(&serialized).expect("rule must round-trip");
    assert_eq!(*rule, reparsed);
}
