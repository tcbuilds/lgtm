//! Keep user-facing Codex protocol claims aligned with the adapter contract.

#[test]
fn codex_docs_state_current_response_and_enforcement_limits() {
    let docs = include_str!("../doc/adapters/codex.md");
    assert!(docs.contains("exit status `2`"));
    assert!(docs.contains("does not permanently reject the turn"));
    assert!(docs.contains("cannot undo side effects"));
    assert!(docs.contains("not a\nuniversal shell-security boundary"));
}

#[test]
fn codex_adr_preserves_the_same_limits() {
    let adr = include_str!("../doc/adr/0012-codex-native-hooks.md");
    assert!(adr.contains("incomplete interception"));
    assert!(adr.contains("request a continuation"));
    assert!(adr.contains("cannot undo completed side effects"));
}

#[test]
fn codex_docs_publish_the_execution_path_boundary() {
    let docs = include_str!("../doc/adapters/codex.md");
    for term in [
        "Bash",
        "apply_patch",
        "MCP tools",
        "unified_exec",
        "WebSearch",
    ] {
        assert!(docs.contains(term), "capability matrix missing {term}");
    }
    assert!(docs.contains("incomplete"));
    assert!(docs.contains("unsupported"));
}
