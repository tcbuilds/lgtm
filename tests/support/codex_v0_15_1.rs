//! Rebuild the v0.15.1 Codex `AGENTS.md` from the current rendering.
//!
//! v0.15.1 shipped every current template except `state-and-concurrency.md`,
//! and shipped the rule files listed in [`CHANGED_SINCE_V0_15_1`] with the
//! recorded fixture contents. Reverting exactly those sections reproduces the
//! released document byte for byte, which [`V0_15_1_CODEX_DIGEST`] pins.
//!
//! Each test binary that includes this module uses a different subset of it, so
//! unused-item warnings are expected and silenced here.
#![allow(dead_code)]

use lgtm::policy::frontmatter::{RULE_DOCUMENT_SOURCES, body};

/// SHA-256 of the `AGENTS.md` that `lgtm init --agent codex` wrote in v0.12.0
/// through v0.15.1; the document did not change across those releases.
pub const V0_15_1_CODEX_DIGEST: &str =
    "26b46d1976dbe90bf979878cf82650797f46e7bcb2df7887fa896e29d18b4909";

/// The rule document added after v0.15.1.
pub const ADDED_SINCE_V0_15_1: &str = "state-and-concurrency.md";

/// Rule documents changed after v0.15.1, paired with their v0.15.1 contents.
pub const CHANGED_SINCE_V0_15_1: [(&str, &str); 8] = [
    (
        "error-handling.md",
        include_str!("../fixtures/legacy-rules/v0.15.1/error-handling.md"),
    ),
    (
        "code-organization.md",
        include_str!("../fixtures/legacy-rules/v0.15.1/code-organization.md"),
    ),
    (
        "testing.md",
        include_str!("../fixtures/legacy-rules/v0.15.1/testing.md"),
    ),
    (
        "patterns/sql.md",
        include_str!("../fixtures/legacy-rules/v0.15.1/patterns/sql.md"),
    ),
    (
        "config.md",
        include_str!("../fixtures/legacy-rules/v0.15.1/config.md"),
    ),
    (
        "infrastructure.md",
        include_str!("../fixtures/legacy-rules/v0.15.1/infrastructure.md"),
    ),
    (
        "sql.md",
        include_str!("../fixtures/legacy-rules/v0.15.1/sql.md"),
    ),
    (
        "patterns/testing.md",
        include_str!("../fixtures/legacy-rules/v0.15.1/patterns/testing.md"),
    ),
];

/// Return the embedded current contents of one shipped rule document.
pub fn current_rule(name: &str) -> &'static str {
    let source_path = format!("templates/claude-rules/rules/{name}");
    RULE_DOCUMENT_SOURCES
        .iter()
        .find(|(path, _)| *path == source_path)
        .map(|(_, contents)| *contents)
        .unwrap_or_else(|| panic!("embedded rule document {name}"))
}

/// Render one template the way the Codex document separates and inlines it.
pub fn codex_section(contents: &str) -> String {
    format!(
        "\n---\n\n{}\n",
        body(contents).expect("body").trim_start().trim_end()
    )
}

/// Revert the post-v0.15.1 rule changes inside a current Codex document.
pub fn v0_15_1_codex_document(current: &str) -> String {
    let added = codex_section(current_rule(ADDED_SINCE_V0_15_1));
    assert!(
        current.contains(&added),
        "missing Codex section {ADDED_SINCE_V0_15_1}"
    );
    let mut previous = current.replace(&added, "");
    for (name, legacy) in CHANGED_SINCE_V0_15_1 {
        let section = codex_section(current_rule(name));
        assert!(previous.contains(&section), "missing Codex section {name}");
        previous = previous.replace(&section, &codex_section(legacy));
    }
    previous
}
