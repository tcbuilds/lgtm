//! Harness-neutral selection of path-scoped rule document bodies.
//!
//! This module selects guidance only. It does not produce enforcement results,
//! make policy decisions, or retain session state for future calls.

use std::collections::{BTreeSet, HashSet};

use crate::policy::frontmatter::{self, RULE_DOCUMENT_SOURCES};
use crate::select::file_pattern_matches;

pub use crate::path_injection_state::{
    FileSessionDedupStore, MAX_SESSION_DEDUP_SESSIONS, MAX_SESSION_DEDUP_STATE_BYTES,
    NoopSessionDedupStore, SESSION_DEDUP_STATE_RELATIVE_PATH, SessionDedupBeginError,
    SessionDedupStore, SessionDedupStoreError, SessionDedupTransaction,
};

pub const MAX_CANDIDATE_PATHS: usize = 1_024;
pub const MAX_CANDIDATE_PATH_BYTES: usize = 4_096;
pub const MAX_SOURCE_PATH_BYTES: usize = 4_096;
pub const MAX_SESSION_ID_BYTES: usize = 256;
pub const MAX_SOURCE_DOCUMENTS: usize = 256;
pub const MAX_SOURCE_DOCUMENT_BYTES: usize = 256 * 1_024;
pub const MAX_AGGREGATE_BODY_BYTES: usize = 64 * 1_024;
pub const MAX_DIAGNOSTIC_BYTES: usize = 2 * 1_024;
pub const MAX_DOCUMENT_PATTERNS: usize = 256;
pub const MAX_PATTERN_BYTES: usize = 4_096;
pub const MAX_PATTERN_BRACE_DEPTH: usize = 32;
pub const MAX_PATTERN_MATCH_ATTEMPTS: usize = 65_536;
pub const MAX_PATTERN_MATCH_WORK: usize = 64 * 1_024 * 1_024;

/// The compact entry is loaded eagerly through Pi's managed `AGENTS.md` block.
/// Shared path injection must never return that same body a second time.
pub const EAGER_ENTRY_SOURCE_PATH: &str = "templates/claude-rules/CLAUDE.md";

const DIAG_CANDIDATE_LIMIT: &str = "guidance candidate limit exceeded";
const DIAG_CANDIDATE_REJECTED: &str = "guidance candidate rejected";
const DIAG_SESSION_LIMIT: &str = "guidance session id omitted";
const DIAG_SOURCE_LIMIT: &str = "guidance source limit exceeded";
const DIAG_SOURCE_UNREADABLE: &str = "guidance source unreadable";
const DIAG_SOURCE_TOO_LARGE: &str = "guidance source too large";
const DIAG_SOURCE_MALFORMED: &str = "guidance source metadata malformed";
const DIAG_SOURCE_SCOPE_UNSUPPORTED: &str = "guidance source scope unsupported";
const DIAG_SOURCE_PATH_REJECTED: &str = "guidance source path rejected";
const DIAG_AGGREGATE_LIMIT: &str = "guidance aggregate budget exceeded";
const DIAG_MATCH_WORK_LIMIT: &str = "guidance matching work budget exhausted";
const DIAG_SESSION_STATE_UNAVAILABLE: &str = "guidance session state unavailable";
const DIAG_SESSION_STATE_BUSY: &str = "guidance session state busy";

/// Input to path-scoped guidance selection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathInjectionRequest {
    pub candidate_paths: Vec<String>,
    pub session_id: Option<String>,
}

impl PathInjectionRequest {
    pub fn new(candidate_paths: Vec<String>, session_id: Option<String>) -> Self {
        Self {
            candidate_paths,
            session_id,
        }
    }
}

/// A complete rule document body and its logical catalog path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleBody {
    pub source_path: String,
    pub body: String,
}

/// Guidance selection output. Diagnostics describe omitted guidance only; they
/// are not enforcement findings or evidence of policy compliance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathInjectionResult {
    pub session_id: Option<String>,
    pub bodies: Vec<RuleBody>,
    pub diagnostics: Vec<String>,
}

/// Metadata for one catalog document. Metadata probes must not materialize its
/// contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDocumentMetadata {
    pub logical_path: String,
}

impl SourceDocumentMetadata {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            logical_path: path.into(),
        }
    }
}

/// One catalog document supplied to a [`RuleDocumentSource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDocument {
    pub logical_path: String,
    pub contents: Result<String, String>,
}

impl SourceDocument {
    pub fn readable(path: impl Into<String>, contents: impl Into<String>) -> Self {
        Self {
            logical_path: path.into(),
            contents: Ok(contents.into()),
        }
    }

    pub fn unreadable(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            logical_path: path.into(),
            contents: Err(reason.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceDocumentError {
    Unreadable,
    TooLarge,
}

/// Bounded source seam used by tests and future installed-file integrations.
/// Implementations must inspect document size before creating an owned full
/// contents string and must honor `max_bytes` for every document load.
pub trait RuleDocumentSource {
    fn metadata(&self, index: usize) -> Option<SourceDocumentMetadata>;
    fn document(
        &self,
        index: usize,
        max_bytes: usize,
    ) -> Result<Option<SourceDocument>, SourceDocumentError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EmbeddedRuleDocumentSource;

impl RuleDocumentSource for EmbeddedRuleDocumentSource {
    fn metadata(&self, index: usize) -> Option<SourceDocumentMetadata> {
        RULE_DOCUMENT_SOURCES
            .get(index)
            .map(|(path, _)| SourceDocumentMetadata::new(*path))
    }

    fn document(
        &self,
        index: usize,
        max_bytes: usize,
    ) -> Result<Option<SourceDocument>, SourceDocumentError> {
        let Some((path, contents)) = RULE_DOCUMENT_SOURCES.get(index) else {
            return Ok(None);
        };
        if contents.len() > max_bytes {
            return Err(SourceDocumentError::TooLarge);
        }
        Ok(Some(SourceDocument::readable(*path, *contents)))
    }
}

/// Select guidance from the embedded rule-document catalog without persistence.
pub fn select_rule_bodies(request: &PathInjectionRequest) -> PathInjectionResult {
    select_rule_bodies_with_source(request, &EmbeddedRuleDocumentSource)
}

/// Select guidance from an injected catalog source without persistence.
///
/// This compatibility API retains issue #5 behavior. Future adapters should use
/// [`select_rule_bodies_with_source_and_store`] with [`FileSessionDedupStore`].
pub fn select_rule_bodies_with_source(
    request: &PathInjectionRequest,
    source: &dyn RuleDocumentSource,
) -> PathInjectionResult {
    select_rule_bodies_with_source_and_store(request, source, &NoopSessionDedupStore)
}

/// Select guidance from the embedded catalog with an explicit persistent store.
pub fn select_rule_bodies_with_store(
    request: &PathInjectionRequest,
    store: &dyn SessionDedupStore,
) -> PathInjectionResult {
    select_rule_bodies_with_source_and_store(request, &EmbeddedRuleDocumentSource, store)
}

/// Select guidance from an injected catalog source and atomically filter bodies
/// already emitted for the request's usable session id.
pub fn select_rule_bodies_with_source_and_store(
    request: &PathInjectionRequest,
    source: &dyn RuleDocumentSource,
    store: &dyn SessionDedupStore,
) -> PathInjectionResult {
    let mut diagnostics = DiagnosticCollector::default();
    let session_id = request
        .session_id
        .as_deref()
        .and_then(|value| sanitize_session_id(value, &mut diagnostics));
    let candidates = normalize_candidates(&request.candidate_paths, &mut diagnostics);
    if candidates.is_empty() {
        return result(session_id, Vec::new(), diagnostics);
    }

    let mut state = SelectionState {
        diagnostics,
        ..SelectionState::default()
    };
    let mut session_transaction = None;
    if let Some(session_id) = session_id.as_deref() {
        match store.begin(session_id) {
            Ok(transaction) => match transaction.seen() {
                Ok(previously_emitted) => {
                    state.previously_emitted = previously_emitted;
                    session_transaction = Some(transaction);
                }
                Err(_) => state.session_state_unavailable = true,
            },
            Err(SessionDedupBeginError::Contended) => {
                state.diagnostics.push(DIAG_SESSION_STATE_BUSY);
                return result(Some(session_id.to_string()), Vec::new(), state.diagnostics);
            }
            Err(SessionDedupBeginError::Unavailable) => {
                state.session_state_unavailable = true;
            }
        }
    };
    for index in 0..=MAX_SOURCE_DOCUMENTS {
        let Some(metadata) = source.metadata(index) else {
            break;
        };
        if index == MAX_SOURCE_DOCUMENTS {
            state.diagnostics.push(DIAG_SOURCE_LIMIT);
            break;
        }
        if metadata.logical_path == EAGER_ENTRY_SOURCE_PATH {
            continue;
        }
        if !source_path_is_valid(&metadata.logical_path) {
            state.diagnostics.push(DIAG_SOURCE_PATH_REJECTED);
            continue;
        }
        if state.seen_sources.contains(&metadata.logical_path) {
            continue;
        }
        match source.document(index, MAX_SOURCE_DOCUMENT_BYTES) {
            Ok(Some(document)) => process_document(document, &candidates, &mut state),
            Ok(None) | Err(SourceDocumentError::Unreadable) => {
                state.diagnostics.push(DIAG_SOURCE_UNREADABLE)
            }
            Err(SourceDocumentError::TooLarge) => state.diagnostics.push(DIAG_SOURCE_TOO_LARGE),
        }
    }

    if session_id.is_some() {
        apply_session_dedup(&mut state, session_transaction.as_deref_mut());
    } else {
        use_fallback_projection(&mut state);
    }
    drop(session_transaction);
    result(session_id, state.bodies, state.diagnostics)
}

#[derive(Default)]
struct SelectionState {
    seen_sources: HashSet<String>,
    bodies: Vec<RuleBody>,
    body_bytes: usize,
    fallback_bodies: Vec<RuleBody>,
    fallback_body_bytes: usize,
    fallback_aggregate_exceeded: bool,
    aggregate_limit_reported: bool,
    match_attempts: usize,
    match_work: usize,
    match_budget_reported: bool,
    previously_emitted: BTreeSet<String>,
    session_state_unavailable: bool,
    diagnostics: DiagnosticCollector,
}

fn process_document(document: SourceDocument, candidates: &[String], state: &mut SelectionState) {
    let source_identity = document.logical_path;
    if !source_path_is_valid(&source_identity) {
        state.diagnostics.push(DIAG_SOURCE_PATH_REJECTED);
        return;
    }
    if state.seen_sources.contains(&source_identity) {
        return;
    }
    let source_path = source_path(&source_identity);
    let contents = match document.contents {
        Ok(contents) => contents,
        Err(_) => {
            state.diagnostics.push(DIAG_SOURCE_UNREADABLE);
            return;
        }
    };
    if contents.len() > MAX_SOURCE_DOCUMENT_BYTES {
        state.diagnostics.push(DIAG_SOURCE_TOO_LARGE);
        return;
    }

    let frontmatter = match frontmatter::parse_file(&source_path, &contents) {
        Ok(frontmatter) => frontmatter,
        Err(_) => {
            state.diagnostics.push(DIAG_SOURCE_MALFORMED);
            return;
        }
    };
    match document_applies(
        frontmatter.as_ref(),
        candidates,
        &mut state.match_attempts,
        &mut state.match_work,
        &mut state.diagnostics,
    ) {
        ScopeMatch::DoesNotApply => return,
        ScopeMatch::BudgetExhausted => {
            if !state.match_budget_reported {
                state.diagnostics.push(DIAG_MATCH_WORK_LIMIT);
                state.match_budget_reported = true;
            }
            return;
        }
        ScopeMatch::Applies => {}
    }
    let body = match frontmatter::body(&contents) {
        Ok(body) => body,
        Err(_) => {
            state.diagnostics.push(DIAG_SOURCE_MALFORMED);
            return;
        }
    };
    let previously_emitted = state.previously_emitted.contains(&source_identity);
    let rule_body = RuleBody {
        source_path,
        body: body.to_string(),
    };
    if body.len() <= MAX_AGGREGATE_BODY_BYTES.saturating_sub(state.fallback_body_bytes) {
        state.fallback_body_bytes += body.len();
        state.fallback_bodies.push(rule_body.clone());
    } else {
        state.fallback_aggregate_exceeded = true;
    }
    state.seen_sources.insert(source_identity);
    if previously_emitted {
        return;
    }
    if body.len() > MAX_AGGREGATE_BODY_BYTES.saturating_sub(state.body_bytes) {
        state.diagnostics.push(DIAG_AGGREGATE_LIMIT);
        state.aggregate_limit_reported = true;
        return;
    }
    state.body_bytes += body.len();
    state.bodies.push(rule_body);
}

fn apply_session_dedup(
    state: &mut SelectionState,
    transaction: Option<&mut (dyn SessionDedupTransaction + '_)>,
) {
    if state.bodies.is_empty() && state.fallback_bodies.is_empty() {
        return;
    }
    if state.session_state_unavailable {
        state.diagnostics.push(DIAG_SESSION_STATE_UNAVAILABLE);
        use_fallback_projection(state);
        return;
    }
    let Some(transaction) = transaction else {
        state.diagnostics.push(DIAG_SESSION_STATE_UNAVAILABLE);
        use_fallback_projection(state);
        return;
    };
    let source_paths: Vec<_> = state
        .bodies
        .iter()
        .map(|body| body.source_path.clone())
        .collect();
    let Ok(already_seen) = transaction.filter_and_record(&source_paths) else {
        state.diagnostics.push(DIAG_SESSION_STATE_UNAVAILABLE);
        use_fallback_projection(state);
        return;
    };
    state
        .bodies
        .retain(|body| !already_seen.contains(&body.source_path));
}

fn use_fallback_projection(state: &mut SelectionState) {
    state.bodies = std::mem::take(&mut state.fallback_bodies);
    if state.fallback_aggregate_exceeded && !state.aggregate_limit_reported {
        state.diagnostics.push(DIAG_AGGREGATE_LIMIT);
    }
}

fn result(
    session_id: Option<String>,
    bodies: Vec<RuleBody>,
    diagnostics: DiagnosticCollector,
) -> PathInjectionResult {
    PathInjectionResult {
        session_id,
        bodies,
        diagnostics: diagnostics.finish(),
    }
}

fn sanitize_session_id(value: &str, diagnostics: &mut DiagnosticCollector) -> Option<String> {
    if value.is_empty() || value.len() > MAX_SESSION_ID_BYTES || value.chars().any(char::is_control)
    {
        if !value.is_empty() {
            diagnostics.push(DIAG_SESSION_LIMIT);
        }
        return None;
    }
    Some(value.to_string())
}

fn normalize_candidates(
    raw_candidates: &[String],
    diagnostics: &mut DiagnosticCollector,
) -> Vec<String> {
    if raw_candidates.len() > MAX_CANDIDATE_PATHS {
        diagnostics.push(DIAG_CANDIDATE_LIMIT);
    }
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    for raw in raw_candidates.iter().take(MAX_CANDIDATE_PATHS) {
        let Some(candidate) = normalize_candidate(raw, diagnostics) else {
            continue;
        };
        if seen.insert(candidate.clone()) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn normalize_candidate(raw: &str, diagnostics: &mut DiagnosticCollector) -> Option<String> {
    if raw.len() > MAX_CANDIDATE_PATH_BYTES {
        diagnostics.push(DIAG_CANDIDATE_REJECTED);
        return None;
    }
    let normalized = raw.replace('\\', "/");
    let invalid = normalized.trim().is_empty()
        || normalized.chars().any(char::is_control)
        || normalized.starts_with('/')
        || has_drive_prefix(&normalized)
        || normalized.split('/').any(|component| component == "..");
    if invalid {
        diagnostics.push(DIAG_CANDIDATE_REJECTED);
        return None;
    }

    let components: Vec<_> = normalized
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    if components.is_empty() {
        return Some(".".to_string());
    }
    Some(components.join("/"))
}

fn has_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

enum ScopeMatch {
    Applies,
    DoesNotApply,
    BudgetExhausted,
}

fn document_applies(
    frontmatter: Option<&frontmatter::RuleFrontmatter>,
    candidates: &[String],
    match_attempts: &mut usize,
    match_work: &mut usize,
    diagnostics: &mut DiagnosticCollector,
) -> ScopeMatch {
    let Some(frontmatter) = frontmatter else {
        return ScopeMatch::Applies;
    };
    if frontmatter.paths.is_empty() {
        return ScopeMatch::Applies;
    }
    if !patterns_are_safe(&frontmatter.paths) {
        diagnostics.push(DIAG_SOURCE_SCOPE_UNSUPPORTED);
        return ScopeMatch::DoesNotApply;
    }
    for pattern in &frontmatter.paths {
        for candidate in candidates {
            if *match_attempts >= MAX_PATTERN_MATCH_ATTEMPTS {
                return ScopeMatch::BudgetExhausted;
            }
            let work = pattern_match_work(pattern, candidate);
            if work > MAX_PATTERN_MATCH_WORK.saturating_sub(*match_work) {
                return ScopeMatch::BudgetExhausted;
            }
            *match_attempts += 1;
            *match_work += work;
            if file_pattern_matches(pattern, candidate) {
                return ScopeMatch::Applies;
            }
        }
    }
    ScopeMatch::DoesNotApply
}

fn pattern_match_work(pattern: &str, candidate: &str) -> usize {
    pattern.len().saturating_mul(candidate.len().max(1)).max(1)
}

fn patterns_are_safe(patterns: &[String]) -> bool {
    patterns.len() <= MAX_DOCUMENT_PATTERNS
        && patterns.iter().all(|pattern| {
            pattern.len() <= MAX_PATTERN_BYTES && brace_depth(pattern) <= MAX_PATTERN_BRACE_DEPTH
        })
}

fn brace_depth(pattern: &str) -> usize {
    let mut depth: usize = 0;
    let mut maximum: usize = 0;
    for byte in pattern.bytes() {
        match byte {
            b'{' => {
                depth += 1;
                maximum = maximum.max(depth);
            }
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    maximum
}

fn source_path_is_valid(path: &str) -> bool {
    !path.is_empty() && path.len() <= MAX_SOURCE_PATH_BYTES && !path.chars().any(char::is_control)
}

fn source_path(path: &str) -> String {
    path.to_string()
}

#[derive(Debug, Default)]
struct DiagnosticCollector {
    messages: Vec<String>,
    bytes: usize,
}

impl DiagnosticCollector {
    fn push(&mut self, message: &'static str) {
        let remaining = MAX_DIAGNOSTIC_BYTES.saturating_sub(self.bytes);
        if message.len() > remaining {
            return;
        }
        self.bytes += message.len();
        self.messages.push(message.to_string());
    }

    fn finish(self) -> Vec<String> {
        self.messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_candidate_normalization_deduplicates_equivalent_paths() {
        let mut diagnostics = DiagnosticCollector::default();
        let candidates = normalize_candidates(
            &[
                "./src\\service.py".to_string(),
                "src/service.py".to_string(),
                "src//service.py".to_string(),
            ],
            &mut diagnostics,
        );

        assert_eq!(candidates, ["src/service.py"]);
        assert!(diagnostics.messages.is_empty());
    }
}
