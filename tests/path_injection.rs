use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use lgtm::path_injection::{
    EmbeddedRuleDocumentSource, MAX_AGGREGATE_BODY_BYTES, MAX_CANDIDATE_PATH_BYTES,
    MAX_CANDIDATE_PATHS, MAX_DIAGNOSTIC_BYTES, MAX_DOCUMENT_PATTERNS, MAX_PATTERN_BRACE_DEPTH,
    MAX_PATTERN_BYTES, MAX_PATTERN_MATCH_ATTEMPTS, MAX_PATTERN_MATCH_WORK, MAX_SESSION_ID_BYTES,
    MAX_SOURCE_DOCUMENT_BYTES, MAX_SOURCE_DOCUMENTS, MAX_SOURCE_PATH_BYTES, PathInjectionRequest,
    RuleDocumentSource, SourceDocument, SourceDocumentError, SourceDocumentMetadata,
    select_rule_bodies, select_rule_bodies_with_source,
};
use lgtm::policy::frontmatter::RULE_DOCUMENT_SOURCES;

#[derive(Clone)]
struct FakeSource {
    documents: Vec<SourceDocument>,
    calls: Arc<AtomicUsize>,
    payload_loads: Arc<AtomicUsize>,
    sentinel_payload_loads: Arc<AtomicUsize>,
    requested_max_bytes: Arc<Mutex<Vec<usize>>>,
    last_index: Arc<AtomicUsize>,
}

impl RuleDocumentSource for FakeSource {
    fn metadata(&self, index: usize) -> Option<SourceDocumentMetadata> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.last_index.store(index, Ordering::Relaxed);
        self.documents
            .get(index)
            .map(|document| SourceDocumentMetadata::new(document.logical_path.clone()))
    }

    fn document(
        &self,
        index: usize,
        max_bytes: usize,
    ) -> Result<Option<SourceDocument>, SourceDocumentError> {
        self.payload_loads.fetch_add(1, Ordering::Relaxed);
        self.requested_max_bytes
            .lock()
            .expect("max-bytes recording lock")
            .push(max_bytes);
        if index == MAX_SOURCE_DOCUMENTS {
            self.sentinel_payload_loads.fetch_add(1, Ordering::Relaxed);
        }
        let Some(document) = self.documents.get(index) else {
            return Ok(None);
        };
        match &document.contents {
            Ok(contents) if contents.len() > max_bytes => Err(SourceDocumentError::TooLarge),
            Ok(contents) => Ok(Some(SourceDocument::readable(
                document.logical_path.clone(),
                contents.clone(),
            ))),
            Err(_) => Err(SourceDocumentError::Unreadable),
        }
    }
}

struct FakeHarness;

impl FakeHarness {
    fn inject(
        request: &PathInjectionRequest,
        source: &dyn RuleDocumentSource,
    ) -> lgtm::path_injection::PathInjectionResult {
        select_rule_bodies_with_source(request, source)
    }
}

fn source(documents: Vec<SourceDocument>) -> FakeSource {
    FakeSource {
        documents,
        calls: Arc::new(AtomicUsize::new(0)),
        payload_loads: Arc::new(AtomicUsize::new(0)),
        sentinel_payload_loads: Arc::new(AtomicUsize::new(0)),
        requested_max_bytes: Arc::new(Mutex::new(Vec::new())),
        last_index: Arc::new(AtomicUsize::new(0)),
    }
}

fn rule_document(path: &str, paths: &[&str], body: &str) -> SourceDocument {
    let metadata = serde_json::json!({
        "description": "test rule document",
        "paths": paths,
    });
    SourceDocument::readable(path, format!("---\n{metadata}\n---\n{body}"))
}

fn request(paths: &[&str]) -> PathInjectionRequest {
    PathInjectionRequest::new(
        paths.iter().map(|path| (*path).to_string()).collect(),
        Some("session-1".to_string()),
    )
}

#[test]
fn published_service_limits_are_literal_and_stable() {
    assert_eq!(MAX_CANDIDATE_PATHS, 1_024);
    assert_eq!(MAX_CANDIDATE_PATH_BYTES, 4_096);
    assert_eq!(MAX_SESSION_ID_BYTES, 256);
    assert_eq!(MAX_SOURCE_DOCUMENTS, 256);
    assert_eq!(MAX_SOURCE_DOCUMENT_BYTES, 256 * 1_024);
    assert_eq!(MAX_AGGREGATE_BODY_BYTES, 64 * 1_024);
    assert_eq!(MAX_DIAGNOSTIC_BYTES, 2 * 1_024);
    assert_eq!(MAX_DOCUMENT_PATTERNS, 256);
    assert_eq!(MAX_PATTERN_BYTES, 4_096);
    assert_eq!(MAX_PATTERN_BRACE_DEPTH, 32);
    assert_eq!(MAX_PATTERN_MATCH_ATTEMPTS, 65_536);
    assert_eq!(MAX_PATTERN_MATCH_WORK, 64 * 1_024 * 1_024);
    assert_eq!(MAX_SOURCE_PATH_BYTES, 4_096);
}

#[test]
fn fake_harness_selects_matching_bodies_in_catalog_order_without_frontmatter() {
    let source = source(vec![
        rule_document("patterns/python.md", &["**/*.py"], "python pattern body"),
        rule_document("python.md", &["**/*.py"], "python body"),
        rule_document("rust.md", &["**/*.rs"], "rust body"),
    ]);
    let result = FakeHarness::inject(&request(&["src/service.py"]), &source);
    let paths: Vec<_> = result
        .bodies
        .iter()
        .map(|document| document.source_path.as_str())
        .collect();

    assert_eq!(paths, ["patterns/python.md", "python.md"]);
    assert_eq!(result.bodies[0].body, "python pattern body");
    assert!(!result.bodies[0].body.contains("description"));
}

#[test]
fn embedded_catalog_matches_complete_source_order_paths_and_contents() {
    let source = EmbeddedRuleDocumentSource;
    for (index, (expected_path, expected_contents)) in RULE_DOCUMENT_SOURCES.iter().enumerate() {
        let document = source
            .document(index, MAX_SOURCE_DOCUMENT_BYTES)
            .expect("catalog load")
            .expect("catalog document");
        assert_eq!(document.logical_path, *expected_path);
        assert_eq!(document.contents, Ok((*expected_contents).to_string()));
    }
    assert!(source.metadata(RULE_DOCUMENT_SOURCES.len()).is_none());
}

#[test]
fn embedded_catalog_selects_python_and_excludes_rust_and_terraform_guidance() {
    let result = select_rule_bodies(&request(&["src/service.py"]));
    let paths: Vec<_> = result
        .bodies
        .iter()
        .map(|document| document.source_path.as_str())
        .collect();

    let python = "templates/claude-rules/rules/python.md";
    let python_patterns = "templates/claude-rules/rules/patterns/python.md";
    assert!(paths.contains(&python));
    assert!(paths.contains(&python_patterns));
    assert!(
        paths.iter().position(|path| *path == python_patterns)
            < paths.iter().position(|path| *path == python)
    );
    assert!(!paths.contains(&"templates/claude-rules/rules/rust.md"));
    assert!(!paths.contains(&"templates/claude-rules/rules/patterns/rust.md"));
    assert!(!paths.contains(&"templates/claude-rules/rules/infrastructure.md"));
    assert!(
        result
            .bodies
            .iter()
            .all(|document| !document.body.starts_with("---\n"))
    );
}

#[test]
fn matching_candidates_are_normalized_and_do_not_duplicate_documents() {
    let source = source(vec![rule_document(
        "python.md",
        &["**/*.py"],
        "python body",
    )]);
    let request = request(&["src\\service.py", "src/service.py"]);
    let result = FakeHarness::inject(&request, &source);

    assert_eq!(result.bodies.len(), 1);
    assert_eq!(result.bodies[0].body, "python body");
}

#[test]
fn empty_and_unresolvable_candidates_return_no_guidance_before_source_inspection() {
    let source = source(vec![SourceDocument::readable(
        "always.md",
        "would be selected for valid input",
    )]);
    let request = PathInjectionRequest::new(
        vec![
            String::new(),
            "../service.py".to_string(),
            "/tmp/service.py".to_string(),
            "C:\\tmp\\service.py".to_string(),
            "bad\0path".to_string(),
        ],
        None,
    );
    let result = FakeHarness::inject(&request, &source);

    assert!(result.bodies.is_empty());
    assert_eq!(source.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn unsupported_or_nonmatching_globs_do_not_select_a_body() {
    let source = source(vec![
        rule_document("unsupported.md", &["**/[a-z].py"], "unsupported"),
        rule_document("nonmatching.md", &["**/*.rs"], "nonmatching"),
    ]);
    let result = FakeHarness::inject(&request(&["src/service.py"]), &source);

    assert!(result.bodies.is_empty());
}

#[test]
fn malformed_oversized_and_unreadable_sources_are_skipped_before_later_guidance() {
    let oversized =
        SourceDocument::readable("oversized.md", "x".repeat(MAX_SOURCE_DOCUMENT_BYTES + 1));
    let malformed = SourceDocument::readable("malformed.md", "---\n{\n---\nignored");
    let source = source(vec![
        SourceDocument::unreadable("unreadable.md", "disk\nerror\u{0007}"),
        oversized,
        malformed,
        rule_document("valid.md", &["**/*.py"], "later valid body"),
    ]);
    let result = FakeHarness::inject(&request(&["service.py"]), &source);

    assert_eq!(
        result
            .bodies
            .iter()
            .map(|body| body.body.as_str())
            .collect::<Vec<_>>(),
        ["later valid body"]
    );
    assert_eq!(
        result.diagnostics,
        [
            "guidance source unreadable",
            "guidance source too large",
            "guidance source metadata malformed",
        ]
    );
}

#[test]
fn exact_source_limit_is_accepted_and_one_byte_over_is_skipped() {
    let prefix = "---\n{\"description\":\"";
    let suffix = "\"}\n---\nbody";
    let exact_description = "x".repeat(MAX_SOURCE_DOCUMENT_BYTES - prefix.len() - suffix.len());
    let exact =
        SourceDocument::readable("exact.md", format!("{prefix}{exact_description}{suffix}"));
    let over_description = "x".repeat(MAX_SOURCE_DOCUMENT_BYTES - prefix.len() - suffix.len() + 1);
    let over = SourceDocument::readable("over.md", format!("{prefix}{over_description}{suffix}"));
    let source = source(vec![exact, over]);
    let result = FakeHarness::inject(&request(&["service.py"]), &source);

    assert_eq!(
        result
            .bodies
            .iter()
            .map(|body| body.source_path.as_str())
            .collect::<Vec<_>>(),
        ["exact.md"]
    );
    assert_eq!(result.bodies[0].body, "body");
}

#[test]
fn exact_aggregate_limit_is_accepted_and_next_body_is_omitted_whole() {
    let first = SourceDocument::readable("first.md", "a".repeat(MAX_AGGREGATE_BODY_BYTES / 2));
    let second = SourceDocument::readable("second.md", "b".repeat(MAX_AGGREGATE_BODY_BYTES / 2));
    let third = SourceDocument::readable("third.md", "c");
    let source = source(vec![first, second, third]);
    let result = FakeHarness::inject(&request(&["service.py"]), &source);

    assert_eq!(result.bodies.len(), 2);
    assert_eq!(
        result.bodies[0].body.len() + result.bodies[1].body.len(),
        MAX_AGGREGATE_BODY_BYTES
    );
    assert!(
        !result
            .bodies
            .iter()
            .any(|body| body.source_path == "third.md")
    );
    assert_eq!(result.diagnostics, ["guidance aggregate budget exceeded"]);
}

#[test]
fn aggregate_over_budget_document_is_skipped_and_later_fitting_body_survives() {
    let first = SourceDocument::readable("first.md", "a".repeat(MAX_AGGREGATE_BODY_BYTES - 6));
    let over = SourceDocument::readable("over.md", "b".repeat(10));
    let later = SourceDocument::readable("later.md", "later");
    let source = source(vec![first, over, later]);
    let result = FakeHarness::inject(&request(&["service.py"]), &source);

    assert_eq!(
        result
            .bodies
            .iter()
            .map(|body| body.source_path.as_str())
            .collect::<Vec<_>>(),
        ["first.md", "later.md"]
    );
    assert_eq!(result.bodies[1].body, "later");
    assert_eq!(result.diagnostics, ["guidance aggregate budget exceeded"]);
}

#[test]
fn candidate_path_exact_limit_is_accepted_but_extra_paths_are_not_processed() {
    let exact = format!(
        "src/{}.py",
        "a".repeat(MAX_CANDIDATE_PATH_BYTES - "src/.py".len())
    );
    let exact_source = source(vec![rule_document("exact.md", &["**/*.py"], "exact")]);
    let result = FakeHarness::inject(&request(&[&exact]), &exact_source);
    assert_eq!(result.bodies[0].body, "exact");

    let over = format!(
        "src/{}.py",
        "a".repeat(MAX_CANDIDATE_PATH_BYTES - "src/.py".len() + 1)
    );
    let over_source = source(vec![rule_document("over.md", &["**/*.py"], "over")]);
    let result = FakeHarness::inject(&request(&[&over]), &over_source);
    assert!(result.bodies.is_empty());

    let paths: Vec<String> = (0..MAX_CANDIDATE_PATHS)
        .map(|index| {
            if index + 1 == MAX_CANDIDATE_PATHS {
                "src/last.py".to_string()
            } else {
                format!("src/other-{index}.py")
            }
        })
        .collect();
    let last_source = source(vec![rule_document("last.md", &["**/last.py"], "last")]);
    let result = FakeHarness::inject(&PathInjectionRequest::new(paths, None), &last_source);
    assert_eq!(result.bodies[0].body, "last");

    let mut over_count_paths: Vec<String> = (0..MAX_CANDIDATE_PATHS)
        .map(|index| format!("src/other-{index}.py"))
        .collect();
    over_count_paths.push("src/needle.py".to_string());
    let over_count_source = source(vec![rule_document(
        "needle.md",
        &["**/needle.py"],
        "needle",
    )]);
    let result = FakeHarness::inject(
        &PathInjectionRequest::new(over_count_paths, None),
        &over_count_source,
    );
    assert!(result.bodies.is_empty());
}

#[test]
fn pathological_patterns_are_skipped_before_recursive_matching() {
    let deeply_nested = format!("{}x{}", "{".repeat(20_000), "}".repeat(20_000));
    let over_nested = format!("{}x{}", "{".repeat(33), "}".repeat(33));
    let too_many: Vec<String> = (0..=MAX_DOCUMENT_PATTERNS)
        .map(|index| format!("**/other-{index}.py"))
        .collect();
    let too_many_refs: Vec<_> = too_many.iter().map(String::as_str).collect();
    let over_length = format!("{}x", "a".repeat(MAX_PATTERN_BYTES));
    let exact_depth = format!(
        "{}x{}",
        "{".repeat(MAX_PATTERN_BRACE_DEPTH),
        "}".repeat(MAX_PATTERN_BRACE_DEPTH)
    );
    let bounded_source = source(vec![
        rule_document("deep.md", &[&deeply_nested], "deep"),
        rule_document("nested.md", &[&over_nested], "nested"),
        rule_document("length.md", &[&over_length], "length"),
        rule_document("count.md", &too_many_refs, "count"),
        rule_document("valid.md", &["**/*.py"], "later valid"),
        rule_document("exact-depth.md", &[&exact_depth], "exact depth"),
    ]);
    let result = FakeHarness::inject(&request(&["service.py"]), &bounded_source);

    assert_eq!(result.bodies[0].source_path, "valid.md");
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|message| message.as_str() == "guidance source scope unsupported")
            .count(),
        4
    );

    let exact_depth_source = source(vec![rule_document(
        "exact-depth.md",
        &[&exact_depth],
        "exact depth",
    )]);
    let exact_depth_result = FakeHarness::inject(&request(&["x"]), &exact_depth_source);
    assert_eq!(exact_depth_result.bodies[0].body, "exact depth");
}

#[test]
fn exact_pattern_length_is_accepted_and_match_work_is_bounded() {
    let exact_pattern = format!("{}?", "a".repeat(MAX_PATTERN_BYTES - 1));
    let exact_candidate = format!("{}b", "a".repeat(MAX_PATTERN_BYTES - 1));
    let exact_source = source(vec![rule_document(
        "exact-pattern.md",
        &[&exact_pattern],
        "exact pattern",
    )]);
    let result = FakeHarness::inject(&request(&[&exact_candidate]), &exact_source);
    assert_eq!(result.bodies[0].body, "exact pattern");

    let candidates: Vec<String> = (0..MAX_DOCUMENT_PATTERNS)
        .map(|index| format!("src/file-{index}.py"))
        .collect();
    let patterns: Vec<String> = (0..MAX_DOCUMENT_PATTERNS)
        .map(|index| format!("**/other-{index}.py"))
        .collect();
    let pattern_refs: Vec<_> = patterns.iter().map(String::as_str).collect();
    let source = source(vec![
        rule_document("exhausts.md", &pattern_refs, "must be omitted"),
        rule_document("scoped-after.md", &["**/*.py"], "also omitted"),
        SourceDocument::readable("unscoped-after.md", "unscoped survives"),
    ]);
    let result = FakeHarness::inject(&PathInjectionRequest::new(candidates, None), &source);

    assert_eq!(
        result
            .bodies
            .iter()
            .map(|body| body.source_path.as_str())
            .collect::<Vec<_>>(),
        ["unscoped-after.md"]
    );
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|message| message.as_str() == "guidance matching work budget exhausted")
            .count(),
        1
    );
    assert_eq!(
        MAX_DOCUMENT_PATTERNS * MAX_DOCUMENT_PATTERNS,
        MAX_PATTERN_MATCH_ATTEMPTS
    );
}

#[test]
fn weighted_match_work_budget_is_inclusive_at_the_published_limit() {
    let candidate = "b".repeat(1_024);
    let patterns: Vec<String> = (0..64)
        .map(|index| format!("{}{:02x}", "a".repeat(1_022), index))
        .collect();
    let pattern_refs: Vec<_> = patterns.iter().map(String::as_str).collect();
    let source = source(vec![
        rule_document("exact-work.md", &pattern_refs, "must be omitted"),
        SourceDocument::readable("unscoped-after.md", "unscoped survives"),
    ]);
    let result = FakeHarness::inject(&request(&[&candidate]), &source);

    assert_eq!(
        result
            .bodies
            .iter()
            .map(|body| body.source_path.as_str())
            .collect::<Vec<_>>(),
        ["unscoped-after.md"]
    );
    assert!(result.diagnostics.is_empty());
}

#[test]
fn weighted_match_work_budget_stops_large_allowed_matrix() {
    let patterns: Vec<String> = (0..64)
        .map(|index| format!("{}{:02}", "a".repeat(1_018), index))
        .collect();
    let candidates: Vec<String> = (0..64)
        .map(|index| format!("{}{:02}", "b".repeat(1_018), index))
        .collect();
    let pattern_refs: Vec<_> = patterns.iter().map(String::as_str).collect();
    let source = source(vec![rule_document("work.md", &pattern_refs, "omitted")]);
    let result = FakeHarness::inject(&PathInjectionRequest::new(candidates, None), &source);

    assert!(result.bodies.is_empty());
    assert_eq!(
        result.diagnostics,
        ["guidance matching work budget exhausted"]
    );
}

#[test]
fn exact_attempt_budget_allows_matching_on_final_attempt() {
    let patterns: Vec<String> = (0..(MAX_DOCUMENT_PATTERNS - 1))
        .map(|index| format!("**/other-pattern-{index}.py"))
        .chain(std::iter::once("**/needle.py".to_string()))
        .collect();
    let candidates: Vec<String> = (0..(MAX_DOCUMENT_PATTERNS - 1))
        .map(|index| format!("src/other-{index}.py"))
        .chain(std::iter::once("src/needle.py".to_string()))
        .collect();
    let pattern_refs: Vec<_> = patterns.iter().map(String::as_str).collect();
    let source = source(vec![rule_document(
        "final-attempt.md",
        &pattern_refs,
        "selected",
    )]);
    let result = FakeHarness::inject(&PathInjectionRequest::new(candidates, None), &source);

    assert_eq!(result.bodies[0].body, "selected");
    assert!(result.diagnostics.is_empty());
}

#[test]
fn diagnostics_saturate_without_exceeding_the_byte_budget() {
    let candidates: Vec<String> = (0..MAX_CANDIDATE_PATHS)
        .map(|index| format!("../invalid-{index}.py"))
        .collect();
    let result = FakeHarness::inject(
        &PathInjectionRequest::new(candidates, None),
        &source(vec![]),
    );

    assert!(result.bodies.is_empty());
    assert!(result.diagnostics.len() > 1);
    assert!(
        result
            .diagnostics
            .iter()
            .all(|message| message == "guidance candidate rejected")
    );
    assert!(result.diagnostics.iter().map(String::len).sum::<usize>() <= MAX_DIAGNOSTIC_BYTES);
}

#[test]
fn duplicate_rejected_source_does_not_shadow_later_valid_document() {
    let source = source(vec![
        SourceDocument::unreadable("same.md", "disk error"),
        rule_document("same.md", &["**/*.py"], "valid duplicate"),
    ]);
    let result = FakeHarness::inject(&request(&["service.py"]), &source);

    assert_eq!(result.bodies[0].body, "valid duplicate");
    assert_eq!(result.diagnostics, ["guidance source unreadable"]);
}

#[test]
fn invalid_source_path_cannot_shadow_a_distinct_valid_document() {
    let source = source(vec![
        SourceDocument::readable("same\0.md", "invalid body"),
        rule_document("same.md", &["**/*.py"], "valid body"),
    ]);
    let result = FakeHarness::inject(&request(&["service.py"]), &source);

    assert_eq!(result.bodies[0].body, "valid body");
    assert_eq!(result.diagnostics, ["guidance source path rejected"]);
}

#[test]
fn malformed_yaml_paths_are_rejected_and_inline_paths_remain_scoped() {
    let scalar = SourceDocument::readable(
        "scalar.md",
        "---\ndescription: Rust guidance\npaths: \"**/*.rs\"\n---\nrust body",
    );
    let bare = SourceDocument::readable(
        "bare.md",
        "---\ndescription: Bare guidance\npaths:\n---\nbare body",
    );
    let inline = SourceDocument::readable(
        "inline.md",
        "---\ndescription: Python guidance\npaths: [\"**/*.py\"]\n---\npython body",
    );
    let result = FakeHarness::inject(
        &request(&["service.py"]),
        &source(vec![scalar, bare, inline]),
    );

    assert_eq!(result.bodies[0].body, "python body");
    assert_eq!(
        result.diagnostics,
        [
            "guidance source metadata malformed",
            "guidance source metadata malformed"
        ]
    );
}

#[test]
fn accepted_duplicate_source_identity_is_emitted_once() {
    let source = source(vec![
        rule_document("same.md", &["**/*.py"], "first"),
        rule_document("same.md", &["**/*.py"], "second"),
    ]);
    let result = FakeHarness::inject(&request(&["service.py"]), &source);

    assert_eq!(result.bodies.len(), 1);
    assert_eq!(result.bodies[0].body, "first");
}

#[test]
fn hostile_source_text_never_enters_fixed_neutral_diagnostics() {
    let malformed = SourceDocument::readable(
        "<script>passed-compliant-violation</script>",
        "---\n{\"description\":1,\"markup\":\"<script>passed compliant violation</script>\"}\n---\nbody",
    );
    let source = source(vec![
        SourceDocument::unreadable(
            "<script>source-path</script>",
            "<script>passed compliant violation</script>\u{0001}".repeat(100),
        ),
        malformed,
    ]);
    let request = PathInjectionRequest::new(
        vec!["service.py".to_string()],
        Some("session\n<markup>passed violation</markup>".repeat(100)),
    );
    let result = FakeHarness::inject(&request, &source);
    let diagnostics = result.diagnostics.join("|");

    assert!(diagnostics.len() <= MAX_DIAGNOSTIC_BYTES);
    assert!(diagnostics.chars().all(|character| !character.is_control()));
    for forbidden in ["passed", "compliant", "violation", "<script>", "<markup>"] {
        assert!(
            !diagnostics.contains(forbidden),
            "diagnostic leaked {forbidden}"
        );
    }
}

#[test]
fn session_id_at_limit_is_preserved_and_over_limit_is_omitted() {
    let source = source(vec![SourceDocument::readable("body.md", "body")]);
    let exact_id = "x".repeat(MAX_SESSION_ID_BYTES);
    let exact_request =
        PathInjectionRequest::new(vec!["service.py".to_string()], Some(exact_id.clone()));
    let exact_result = FakeHarness::inject(&exact_request, &source);
    assert_eq!(exact_result.session_id, Some(exact_id));
    assert!(exact_result.diagnostics.is_empty());

    let over_request = PathInjectionRequest::new(
        vec!["service.py".to_string()],
        Some("x".repeat(MAX_SESSION_ID_BYTES + 1)),
    );
    let over_result = FakeHarness::inject(&over_request, &source);
    assert!(over_result.session_id.is_none());
    assert_eq!(over_result.bodies[0].body, "body");
    assert_eq!(over_result.diagnostics, ["guidance session id omitted"]);
}

#[test]
fn last_allowed_source_is_processed_and_excess_probe_is_not_materialized() {
    let mut documents: Vec<_> = (0..(MAX_SOURCE_DOCUMENTS - 1))
        .map(|index| rule_document(&format!("other-{index}.md"), &["**/*.rs"], "other"))
        .collect();
    documents.push(rule_document("last.md", &["**/*.py"], "last"));
    documents.push(rule_document("excess.md", &["**/*.py"], "excess"));
    let source = source(documents);
    let result = FakeHarness::inject(&request(&["service.py"]), &source);

    assert_eq!(
        result.bodies.last().map(|body| body.source_path.as_str()),
        Some("last.md")
    );
    assert!(
        !result
            .bodies
            .iter()
            .any(|body| body.source_path == "excess.md")
    );
    assert_eq!(
        source.calls.load(Ordering::Relaxed),
        MAX_SOURCE_DOCUMENTS + 1
    );
    assert_eq!(
        source.last_index.load(Ordering::Relaxed),
        MAX_SOURCE_DOCUMENTS
    );
    assert_eq!(result.diagnostics, ["guidance source limit exceeded"]);
    assert_eq!(
        source.calls.load(Ordering::Relaxed),
        MAX_SOURCE_DOCUMENTS + 1
    );
    assert_eq!(
        source.payload_loads.load(Ordering::Relaxed),
        MAX_SOURCE_DOCUMENTS
    );
    assert_eq!(source.sentinel_payload_loads.load(Ordering::Relaxed), 0);
    let requested_max_bytes = source
        .requested_max_bytes
        .lock()
        .expect("max-bytes recording lock");
    assert_eq!(requested_max_bytes.len(), MAX_SOURCE_DOCUMENTS);
    assert!(
        requested_max_bytes
            .iter()
            .all(|value| *value == MAX_SOURCE_DOCUMENT_BYTES)
    );
}

#[test]
fn embedded_source_implements_the_bounded_public_source_seam() {
    let source = EmbeddedRuleDocumentSource;
    assert!(source.metadata(0).is_some());
    assert!(
        source
            .document(0, MAX_SOURCE_DOCUMENT_BYTES)
            .expect("catalog load")
            .is_some()
    );
    assert!(source.metadata(RULE_DOCUMENT_SOURCES.len()).is_none());
}
