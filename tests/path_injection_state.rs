#![cfg(unix)]

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicU64, Ordering},
};

use lgtm::path_injection::{
    FileSessionDedupStore, MAX_AGGREGATE_BODY_BYTES, MAX_DIAGNOSTIC_BYTES,
    MAX_SESSION_DEDUP_SESSIONS, MAX_SESSION_DEDUP_STATE_BYTES, MAX_SESSION_ID_BYTES,
    MAX_SOURCE_DOCUMENTS, MAX_SOURCE_PATH_BYTES, PathInjectionRequest, RuleDocumentSource,
    SessionDedupStore, SourceDocument, select_rule_bodies_with_source_and_store,
};

struct TempState {
    root: PathBuf,
    path: PathBuf,
}

impl TempState {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lgtm-path-injection-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("state temp directory");
        std::fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private state temp directory");
        Self {
            path: root.join("sessions.json"),
            root,
        }
    }
}

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_tmp_alias_supports_persistent_state_traversal() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = Path::new("/tmp").join(format!(
        "lgtm-path-injection-macos-tmp-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).expect("macOS /tmp fixture");
    std::fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("private macOS /tmp fixture");
    let state = TempState {
        path: root.join("sessions.json"),
        root,
    };
    let store = FileSessionDedupStore::new(&state.path);

    assert!(
        store
            .filter_and_record("session", &["source.md".to_string()])
            .expect("store through /tmp alias")
            .is_empty()
    );
    assert_eq!(
        store.seen("session").expect("load through /tmp alias"),
        BTreeSet::from(["source.md".to_string()])
    );
}

fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(contents.as_ref())?;
    drop(file);
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
}

fn persistent_request(session_id: &str) -> PathInjectionRequest {
    PathInjectionRequest::new(
        vec!["src/service.py".to_string()],
        Some(session_id.to_string()),
    )
}

fn source(path: &str, body: impl Into<String>) -> SourceDocument {
    SourceDocument::readable(path, body)
}

fn store_request(
    state: &TempState,
    session_id: &str,
    documents: Vec<SourceDocument>,
) -> lgtm::path_injection::PathInjectionResult {
    let store = FileSessionDedupStore::new(&state.path);
    let source = TestSource { documents };
    select_rule_bodies_with_source_and_store(&persistent_request(session_id), &source, &store)
}

struct TestSource {
    documents: Vec<SourceDocument>,
}

impl RuleDocumentSource for TestSource {
    fn metadata(&self, index: usize) -> Option<lgtm::path_injection::SourceDocumentMetadata> {
        self.documents.get(index).map(|document| {
            lgtm::path_injection::SourceDocumentMetadata::new(document.logical_path.clone())
        })
    }

    fn document(
        &self,
        index: usize,
        max_bytes: usize,
    ) -> Result<Option<SourceDocument>, lgtm::path_injection::SourceDocumentError> {
        let Some(document) = self.documents.get(index) else {
            return Ok(None);
        };
        match &document.contents {
            Ok(contents) if contents.len() > max_bytes => {
                Err(lgtm::path_injection::SourceDocumentError::TooLarge)
            }
            Ok(contents) => Ok(Some(SourceDocument::readable(
                document.logical_path.clone(),
                contents.clone(),
            ))),
            Err(_) => Err(lgtm::path_injection::SourceDocumentError::Unreadable),
        }
    }
}

#[test]
fn previously_emitted_large_body_does_not_starve_new_guidance() {
    let state = TempState::new("aggregate-dedup-order");
    let large = source("large.md", "x".repeat(MAX_AGGREGATE_BODY_BYTES));
    let small = source("small.md", "small");

    let first = store_request(&state, "session", vec![large.clone()]);
    let second = store_request(&state, "session", vec![large.clone(), small.clone()]);
    let third = store_request(&state, "session", vec![large, small]);

    assert_eq!(
        first
            .bodies
            .iter()
            .map(|body| body.source_path.as_str())
            .collect::<Vec<_>>(),
        ["large.md"]
    );
    assert_eq!(
        second
            .bodies
            .iter()
            .map(|body| body.source_path.as_str())
            .collect::<Vec<_>>(),
        ["small.md"]
    );
    assert!(third.bodies.is_empty());
}

#[test]
fn control_session_ids_are_omitted_without_aliasing() {
    let state = TempState::new("control-session");
    let document = source("rule.md", "body");
    let control = store_request(&state, "same\nsession", vec![document.clone()]);
    let clean = store_request(&state, "samesession", vec![document.clone()]);
    let clean_retry = store_request(&state, "samesession", vec![document]);

    assert!(control.session_id.is_none());
    assert_eq!(control.diagnostics, ["guidance session id omitted"]);
    assert_eq!(clean.bodies.len(), 1);
    assert!(clean_retry.bodies.is_empty());
}

#[test]
fn empty_source_path_is_rejected_and_literal_placeholder_is_preserved() {
    let state = TempState::new("source-identity");
    let result = store_request(
        &state,
        "session",
        vec![source("", "empty"), source("<unnamed>", "literal")],
    );

    assert_eq!(result.bodies.len(), 1);
    assert_eq!(result.bodies[0].source_path, "<unnamed>");
    assert!(
        result
            .diagnostics
            .contains(&"guidance source path rejected".to_string())
    );
}

#[test]
fn duplicate_identities_in_one_store_batch_are_not_seen_until_the_next_call() {
    let state = TempState::new("duplicate-batch");
    let store = FileSessionDedupStore::new(&state.path);
    let paths = vec!["same.md".to_string(), "same.md".to_string()];

    assert!(
        store
            .filter_and_record("session", &paths)
            .expect("first batch")
            .is_empty()
    );
    assert_eq!(
        store
            .filter_and_record("session", &["same.md".to_string()])
            .expect("retry"),
        BTreeSet::from(["same.md".to_string()])
    );
}

#[test]
fn source_count_rejection_happens_before_parent_creation() {
    let state = TempState::new("source-count");
    let nested = state.root.join("missing").join("sessions.json");
    let store = FileSessionDedupStore::new(&nested);
    let paths = (0..=MAX_SOURCE_DOCUMENTS)
        .map(|index| format!("source-{index}.md"))
        .collect::<Vec<_>>();

    assert!(store.filter_and_record("session", &paths).is_err());
    assert!(!state.root.join("missing").exists());
}

#[test]
fn session_and_source_caps_evict_deterministically_and_keep_new_entries() {
    let state = TempState::new("caps");
    let store = FileSessionDedupStore::new(&state.path);
    for index in 0..=MAX_SESSION_DEDUP_SESSIONS {
        assert!(
            store
                .filter_and_record(
                    &format!("session-{index:03}"),
                    &[format!("source-{index}.md")]
                )
                .expect("session insert")
                .is_empty()
        );
    }
    assert_eq!(
        store
            .filter_and_record("session-064", &["source-64.md".to_string()])
            .expect("new session retry"),
        BTreeSet::from(["source-64.md".to_string()])
    );
    assert!(
        store
            .seen("session-000")
            .expect("evicted session")
            .is_empty()
    );
    assert_eq!(
        store.seen("session-001").expect("retained session"),
        BTreeSet::from(["source-1.md".to_string()])
    );

    let source_paths = (0..MAX_SOURCE_DOCUMENTS)
        .map(|index| format!("source-{index:03}.md"))
        .collect::<Vec<_>>();
    let session = "source-cap";
    store
        .filter_and_record(session, &source_paths)
        .expect("source inserts");
    store
        .filter_and_record(session, &["source-256.md".to_string()])
        .expect("new source");
    assert_eq!(
        store
            .filter_and_record(session, &["source-256.md".to_string()])
            .expect("new source retry"),
        BTreeSet::from(["source-256.md".to_string()])
    );
    assert_eq!(
        store
            .filter_and_record(session, &["source-001.md".to_string()])
            .expect("retained source"),
        BTreeSet::from(["source-001.md".to_string()])
    );
    assert!(
        store
            .filter_and_record(session, &["source-000.md".to_string()])
            .expect("evicted source")
            .is_empty()
    );
}

#[test]
fn source_cap_batch_eviction_preserves_every_new_identity() {
    let state = TempState::new("source-cap-batch");
    let store = FileSessionDedupStore::new(&state.path);
    let initial = (0..MAX_SOURCE_DOCUMENTS)
        .map(|index| format!("z-source-{index:03}.md"))
        .collect::<Vec<_>>();

    assert!(
        store
            .filter_and_record("session", &initial)
            .expect("initial sources")
            .is_empty()
    );
    assert!(
        store
            .filter_and_record(
                "session",
                &["!new-a.md".to_string(), "!new-b.md".to_string()],
            )
            .expect("new batch")
            .is_empty()
    );
    assert_eq!(
        store
            .filter_and_record(
                "session",
                &["!new-a.md".to_string(), "!new-b.md".to_string()],
            )
            .expect("new batch retry"),
        BTreeSet::from(["!new-a.md".to_string(), "!new-b.md".to_string()])
    );
    let seen = store.seen("session").expect("bounded source set");
    assert_eq!(seen.len(), MAX_SOURCE_DOCUMENTS);
    assert!(!seen.contains("z-source-000.md"));
    assert!(!seen.contains("z-source-001.md"));
    assert!(seen.contains("z-source-002.md"));
    assert!(seen.contains("!new-a.md"));
    assert!(seen.contains("!new-b.md"));
}

fn valid_state_with_size(target: usize) -> Vec<u8> {
    for padding in 0..=MAX_SOURCE_PATH_BYTES {
        let mut paths = (0..MAX_SOURCE_DOCUMENTS)
            .map(|index| format!("p-{index}-{}", "x".repeat(padding)))
            .collect::<Vec<_>>();
        let json = serde_json::json!({"sessions": {"session": paths}});
        let bytes = serde_json::to_vec(&json).expect("valid state");
        if bytes.len() > target {
            continue;
        }
        let additional = target - bytes.len();
        let last = paths.last_mut().expect("source paths");
        if last.len() + additional > MAX_SOURCE_PATH_BYTES {
            continue;
        }
        last.extend(std::iter::repeat_n('x', additional));
        let json = serde_json::json!({"sessions": {"session": paths}});
        let bytes = serde_json::to_vec(&json).expect("sized state");
        if bytes.len() == target {
            return bytes;
        }
    }
    panic!("could not construct valid state at {target} bytes");
}

#[test]
fn schema_boundaries_reject_invalid_state_and_accept_exact_caps() {
    let cases = [
        (r#"{"sessions":{},"extra":true}"#, "unknown field"),
        (
            r#"{"sessions":{"s0":[],"s1":[],"s2":[],"s3":[],"s4":[],"s5":[],"s6":[],"s7":[],"s8":[],"s9":[],"s10":[],"s11":[],"s12":[],"s13":[],"s14":[],"s15":[],"s16":[],"s17":[],"s18":[],"s19":[],"s20":[],"s21":[],"s22":[],"s23":[],"s24":[],"s25":[],"s26":[],"s27":[],"s28":[],"s29":[],"s30":[],"s31":[],"s32":[],"s33":[],"s34":[],"s35":[],"s36":[],"s37":[],"s38":[],"s39":[],"s40":[],"s41":[],"s42":[],"s43":[],"s44":[],"s45":[],"s46":[],"s47":[],"s48":[],"s49":[],"s50":[],"s51":[],"s52":[],"s53":[],"s54":[],"s55":[],"s56":[],"s57":[],"s58":[],"s59":[],"s60":[],"s61":[],"s62":[],"s63":[],"s64":[]}}"#,
            "too many sessions",
        ),
        ("invalid", "invalid JSON"),
    ];
    for (index, (contents, _name)) in cases.into_iter().enumerate() {
        let state = TempState::new(&format!("schema-{index}"));
        write_private(&state.path, contents).expect("schema fixture");
        let store = FileSessionDedupStore::new(&state.path);
        assert!(store.seen("session").is_err());
    }

    let too_many_paths = TempState::new("schema-too-many-paths");
    let paths = (0..=MAX_SOURCE_DOCUMENTS)
        .map(|index| format!("p-{index}"))
        .collect::<Vec<_>>();
    let json = serde_json::json!({"sessions": {"session": paths}});
    write_private(
        &too_many_paths.path,
        serde_json::to_vec(&json).expect("valid state"),
    )
    .expect("state");
    assert!(
        FileSessionDedupStore::new(&too_many_paths.path)
            .seen("session")
            .is_err()
    );

    let exact_paths = TempState::new("schema-exact-paths");
    let paths = (0..MAX_SOURCE_DOCUMENTS)
        .map(|index| format!("p-{index}"))
        .collect::<Vec<_>>();
    let json = serde_json::json!({"sessions": {"session": paths}});
    write_private(
        &exact_paths.path,
        serde_json::to_vec(&json).expect("valid state"),
    )
    .expect("state");
    assert_eq!(
        FileSessionDedupStore::new(&exact_paths.path)
            .seen("session")
            .expect("exact source cap")
            .len(),
        MAX_SOURCE_DOCUMENTS
    );

    let exact_sessions = TempState::new("schema-exact-sessions");
    let sessions = (0..MAX_SESSION_DEDUP_SESSIONS)
        .map(|index| (format!("session-{index}"), serde_json::json!([])))
        .collect::<serde_json::Map<_, _>>();
    let json = serde_json::json!({"sessions": sessions});
    write_private(
        &exact_sessions.path,
        serde_json::to_vec(&json).expect("valid state"),
    )
    .expect("state");
    assert!(
        FileSessionDedupStore::new(&exact_sessions.path)
            .seen("session-63")
            .is_ok()
    );

    let invalid_state = TempState::new("schema-invalid-identity");
    let json = serde_json::json!({"sessions": {"bad\nid": []}});
    write_private(
        &invalid_state.path,
        serde_json::to_vec(&json).expect("invalid identity state"),
    )
    .expect("invalid identity state");
    assert!(
        FileSessionDedupStore::new(&invalid_state.path)
            .seen("session")
            .is_err()
    );
}

#[test]
fn state_byte_limit_accepts_exact_valid_json_and_rejects_one_byte_over() {
    let exact = TempState::new("state-exact-bytes");
    write_private(
        &exact.path,
        valid_state_with_size(MAX_SESSION_DEDUP_STATE_BYTES),
    )
    .expect("exact state");
    let store = FileSessionDedupStore::new(&exact.path);
    assert_eq!(
        store.seen("session").expect("exact state load").len(),
        MAX_SOURCE_DOCUMENTS
    );
    store
        .filter_and_record("session", &[])
        .expect("exact state no-op record");

    let over = TempState::new("state-over-bytes");
    let mut over_bytes = valid_state_with_size(MAX_SESSION_DEDUP_STATE_BYTES);
    over_bytes.push(b' ');
    write_private(&over.path, over_bytes).expect("over state");
    assert!(
        FileSessionDedupStore::new(&over.path)
            .seen("session")
            .is_err()
    );
}

#[test]
fn store_rejects_invalid_identities_before_filesystem_work() {
    let session_cases = vec![
        String::new(),
        "bad\nsession".to_string(),
        "x".repeat(MAX_SESSION_ID_BYTES + 1),
    ];
    for session_id in session_cases {
        let state = TempState::new("invalid-session-input");
        let store = FileSessionDedupStore::new(&state.path);
        assert!(store.seen(&session_id).is_err(), "session: {session_id:?}");
        assert!(store.filter_and_record(&session_id, &[]).is_err());
        assert!(!state.path.exists());
    }

    let exact_session = "x".repeat(MAX_SESSION_ID_BYTES);
    let exact_source = "p".repeat(MAX_SOURCE_PATH_BYTES);
    let accepted = TempState::new("exact-identities");
    let store = FileSessionDedupStore::new(&accepted.path);
    assert!(
        store
            .filter_and_record(&exact_session, std::slice::from_ref(&exact_source))
            .is_ok()
    );
    assert_eq!(
        store.seen(&exact_session).expect("exact identities").len(),
        1
    );

    let source_cases = [
        String::new(),
        "bad\nsource".to_string(),
        "p".repeat(MAX_SOURCE_PATH_BYTES + 1),
    ];
    for source_path in source_cases {
        let state = TempState::new("invalid-source-input");
        let store = FileSessionDedupStore::new(&state.path);
        assert!(
            store
                .filter_and_record("session", std::slice::from_ref(&source_path))
                .is_err(),
            "source: {source_path:?}"
        );
        assert!(!state.path.exists());
    }
}

#[test]
fn persisted_invalid_identities_are_rejected() {
    let session_cases = [
        String::new(),
        "bad\nsession".to_string(),
        "x".repeat(MAX_SESSION_ID_BYTES + 1),
    ];
    for session_id in session_cases {
        let state = TempState::new("persisted-invalid-session");
        let json = serde_json::json!({"sessions": {session_id: []}});
        write_private(&state.path, serde_json::to_vec(&json).expect("state"))
            .expect("persisted session");
        assert!(
            FileSessionDedupStore::new(&state.path)
                .seen("session")
                .is_err()
        );
    }

    let source_cases = [
        String::new(),
        "bad\nsource".to_string(),
        "p".repeat(MAX_SOURCE_PATH_BYTES + 1),
    ];
    for source_path in source_cases {
        let state = TempState::new("persisted-invalid-source");
        let json = serde_json::json!({"sessions": {"session": [source_path]}});
        write_private(&state.path, serde_json::to_vec(&json).expect("state"))
            .expect("persisted source");
        assert!(
            FileSessionDedupStore::new(&state.path)
                .seen("session")
                .is_err()
        );
    }
}

#[test]
fn fifo_lock_fails_open_with_fixed_diagnostics() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;

    let state = TempState::new("fifo-lock");
    let lock_path = state.path.with_extension("lock");
    let lock_name = CString::new(lock_path.as_os_str().as_bytes()).expect("lock path");
    // SAFETY: the path is a private test directory and the mode is restrictive.
    let result = unsafe { libc::mkfifo(lock_name.as_ptr(), 0o600) };
    assert_eq!(
        result,
        0,
        "create lock FIFO: {}",
        std::io::Error::last_os_error()
    );

    let (sender, receiver) = std::sync::mpsc::channel();
    let path = state.path.clone();
    std::thread::spawn(move || {
        let store = FileSessionDedupStore::new(path);
        let source = TestSource {
            documents: vec![source("rule.md", "body")],
        };
        let result = select_rule_bodies_with_source_and_store(
            &persistent_request("session"),
            &source,
            &store,
        );
        let _ = sender.send(result);
    });
    // Keep the timeout long enough for the parallel release suite while still
    // failing a genuinely blocking FIFO open instead of hanging indefinitely.
    let result = receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("FIFO lock attempt must be bounded");

    assert_eq!(result.bodies.len(), 1);
    assert_eq!(result.diagnostics, ["guidance session state unavailable"]);
    assert!(
        std::fs::symlink_metadata(lock_path)
            .expect("lock metadata")
            .file_type()
            .is_fifo()
    );
}

#[test]
fn nonregular_state_file_fails_open_without_opening_it() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;

    let state = TempState::new("fifo-state");
    let state_name = CString::new(state.path.as_os_str().as_bytes()).expect("state path");
    // SAFETY: the path is a private test directory and the mode is restrictive.
    let result = unsafe { libc::mkfifo(state_name.as_ptr(), 0o600) };
    assert_eq!(
        result,
        0,
        "create state FIFO: {}",
        std::io::Error::last_os_error()
    );

    let result = store_request(&state, "session", vec![source("rule.md", "body")]);

    assert_eq!(result.bodies.len(), 1);
    assert_eq!(result.diagnostics, ["guidance session state unavailable"]);
    assert!(
        std::fs::symlink_metadata(&state.path)
            .expect("state metadata")
            .file_type()
            .is_fifo()
    );
}

#[test]
fn trusted_private_ancestor_allows_missing_state_directories() {
    use std::os::unix::fs::PermissionsExt;

    let state = TempState::new("private-ancestor");
    let ancestor = state.root.join("private");
    std::fs::create_dir(&ancestor).expect("ancestor directory");
    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o700))
        .expect("private ancestor permissions");
    let store = FileSessionDedupStore::new(ancestor.join("evidence/sessions.json"));

    assert!(
        store
            .filter_and_record("session", &["source.md".to_string()])
            .expect("private ancestor state")
            .is_empty()
    );
    assert!(ancestor.join("evidence/sessions.json").exists());
}

#[test]
fn untrusted_writable_ancestor_fails_open_without_state_creation() {
    use std::os::unix::fs::PermissionsExt;

    let state = TempState::new("writable-ancestor");
    let ancestor = state.root.join("shared");
    std::fs::create_dir(&ancestor).expect("ancestor directory");
    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o777))
        .expect("writable ancestor permissions");
    let store = FileSessionDedupStore::new(ancestor.join("evidence/sessions.json"));

    assert!(
        store
            .filter_and_record("session", &["source.md".to_string()])
            .is_err()
    );
    assert!(!ancestor.join("evidence").exists());
}

#[test]
fn ancestor_symlink_cannot_redirect_state_outside_the_repository() {
    use std::os::unix::fs::symlink;

    let state = TempState::new("symlink-parent");
    let outside = TempState::new("symlink-outside");
    let lgtm = state.root.join(".lgtm");
    std::fs::create_dir_all(&outside.root).expect("outside directory");
    symlink(&outside.root, &lgtm).expect("ancestor symlink");
    let store = FileSessionDedupStore::new(state.root.join(".lgtm/evidence/sessions.json"));

    let result = store.filter_and_record("session", &["source.md".to_string()]);

    assert!(result.is_err());
    assert!(!outside.root.join("evidence").exists());
}

#[test]
fn concurrent_store_instances_emit_one_body_for_one_session() {
    let state = TempState::new("concurrent");
    let path = Arc::new(state.path.clone());
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let handles = (0..2)
            .map(|_| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let source = TestSource {
                        documents: vec![source("rule.md", "body")],
                    };
                    let store = FileSessionDedupStore::new(path.as_ref());
                    barrier.wait();
                    select_rule_bodies_with_source_and_store(
                        &persistent_request("concurrent-session"),
                        &source,
                        &store,
                    )
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("concurrent selection"))
            .collect::<Vec<_>>()
    });

    let mut body_counts = results
        .iter()
        .map(|result| result.bodies.len())
        .collect::<Vec<_>>();
    body_counts.sort_unstable();
    assert_eq!(body_counts, [0, 1]);
    assert!(results.iter().all(|result| result.diagnostics.is_empty()));
}

#[test]
fn healthy_lock_contention_is_busy_without_duplicate_guidance() {
    let state = TempState::new("busy-contention");
    let store = FileSessionDedupStore::new(&state.path);
    let transaction = store.begin("busy-session").expect("held transaction");
    let path = state.path.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let store = FileSessionDedupStore::new(path);
        let source = TestSource {
            documents: vec![source("rule.md", "body")],
        };
        let result = select_rule_bodies_with_source_and_store(
            &persistent_request("busy-session"),
            &source,
            &store,
        );
        let _ = sender.send(result);
    });
    let result = receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("contention selection must be bounded");
    assert!(result.bodies.is_empty());
    assert_eq!(result.diagnostics, ["guidance session state busy"]);
    drop(transaction);
}

#[test]
fn interleaved_sessions_keep_old_and_new_sources_selective() {
    let state = TempState::new("interleaved");
    let old = source("old.md", "old");
    let new = source("new.md", "new");
    let first = store_request(&state, "session-a", vec![old.clone()]);
    let second = store_request(&state, "session-a", vec![old.clone(), new.clone()]);
    let other = store_request(&state, "session-b", vec![old, new.clone()]);
    let retry = store_request(&state, "session-a", vec![new]);

    assert_eq!(first.bodies.len(), 1);
    assert_eq!(
        second
            .bodies
            .iter()
            .map(|body| body.source_path.as_str())
            .collect::<Vec<_>>(),
        ["new.md"]
    );
    assert_eq!(other.bodies.len(), 2);
    assert!(retry.bodies.is_empty());
    assert!(retry.diagnostics.len() <= MAX_DIAGNOSTIC_BYTES);
}

#[test]
fn oversized_state_still_fails_open_with_fixed_diagnostics() {
    let state = TempState::new("oversized-state");
    write_private(
        &state.path,
        valid_state_with_size(MAX_SESSION_DEDUP_STATE_BYTES + 1),
    )
    .expect("oversized state");
    let result = store_request(&state, "session", vec![source("rule.md", "body")]);

    assert_eq!(result.bodies.len(), 1);
    assert_eq!(result.diagnostics, ["guidance session state unavailable"]);
}
