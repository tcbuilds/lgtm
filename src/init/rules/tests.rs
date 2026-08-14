use super::*;

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::super::template_digests::{
    CURRENT_GENERATED_DOCUMENT_DIGESTS, CURRENT_TEMPLATE_DIGESTS, current_template_digest,
};

fn temp_root(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("lgtm-rules-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp root");
    root
}

#[test]
fn every_template_has_a_description_and_scoped_templates_declare_paths() {
    for (relative, contents) in TEMPLATES {
        let frontmatter = contents
            .strip_prefix("---\n")
            .and_then(|contents| contents.split_once("\n---\n"))
            .map(|(frontmatter, _)| frontmatter)
            .expect("template frontmatter");
        assert!(
            frontmatter
                .lines()
                .any(|line| line.starts_with("description: ")),
            "{relative} must describe itself for compatible rule loaders"
        );
        if *relative == "standards.md" {
            assert!(
                !frontmatter.lines().any(|line| line == "paths:"),
                "the entry document must load every session, so it carries no paths frontmatter"
            );
            continue;
        }
        assert!(
            frontmatter.lines().any(|line| line == "paths:"),
            "{relative} must declare a paths glob so it loads only for matching files"
        );
    }
}

#[test]
fn shipped_entry_template_contains_the_native_loading_marker() {
    let entry = TEMPLATES
        .iter()
        .find(|(relative, _)| *relative == "standards.md")
        .map(|(_, contents)| *contents)
        .expect("entry template");
    assert!(
        entry
            .lines()
            .any(|line| line.trim() == ENTRY_DOCUMENT_MARKER)
    );
}

/// Keep the checked-in current digest ledger synchronized with every embedded file.
#[test]
fn every_current_template_has_a_matching_digest_record() {
    assert_eq!(CURRENT_TEMPLATE_DIGESTS.len(), TEMPLATES.len());
    for (relative, contents) in TEMPLATES {
        let expected = format!("{:x}", Sha256::digest(contents.as_bytes()));
        assert_eq!(
            current_template_digest(relative),
            Some(expected.as_str()),
            "{relative} needs a new current-template digest record"
        );
    }
}

/// Keep the current concatenated Codex document digest synchronized with its templates.
#[test]
fn current_generated_document_has_a_matching_digest_record() {
    assert_eq!(CURRENT_GENERATED_DOCUMENT_DIGESTS.len(), 1);
    let expected = format!("{:x}", Sha256::digest(agents_document().as_bytes()));
    assert_eq!(CURRENT_GENERATED_DOCUMENT_DIGESTS[0].path, "AGENTS.md");
    assert_eq!(CURRENT_GENERATED_DOCUMENT_DIGESTS[0].sha256, expected);
}

#[test]
fn every_legacy_release_digest_covers_its_shipped_template_paths() {
    for release in ["v0.5.0", "v0.6.0"] {
        let records: Vec<_> = LEGACY_TEMPLATE_DIGESTS
            .iter()
            .filter(|record| record.release == release)
            .collect();
        assert_eq!(
            records.len(),
            24,
            "{release} generated digest count changed"
        );
        let paths: BTreeSet<_> = records.iter().map(|record| record.path).collect();
        assert_eq!(
            paths.len(),
            records.len(),
            "{release} has duplicate digest paths"
        );
        assert!(
            paths.contains("AGENTS.md"),
            "{release} is missing AGENTS.md digest"
        );
        for record in records {
            if record.path != "AGENTS.md" {
                assert!(
                    TEMPLATES.iter().any(|(path, _)| *path == record.path),
                    "{release} digest references unknown template path {}",
                    record.path
                );
            }
            assert_eq!(record.sha256.len(), 64);
        }
    }
}

#[test]
fn installs_every_template_under_the_rules_directory() {
    let root = temp_root("fresh");
    let outcome = install(&root).expect("install");
    assert_eq!(outcome.written.len(), TEMPLATES.len());
    assert!(outcome.kept.is_empty());
    assert!(root.join(".claude/rules/standards.md").is_file());
    assert!(root.join(".claude/rules/patterns/core.md").is_file());
    std::fs::remove_dir_all(root).ok();
}

/// A symlink on the way to the repository must not be mistaken for one inside it.
///
/// The ancestor walk previously ran to the filesystem root, so any symlink above
/// the repository refused the install. That is the ordinary layout on macOS,
/// where `std::env::temp_dir()` yields `/var/folders/...` and `/var` is a symlink
/// to `/private/var`, and it reaches this test through an unresolved root rather
/// than through `getcwd`, which would have flattened it. The guard covers escapes
/// out of the repository, not the path used to reach it.
#[cfg(unix)]
#[test]
fn a_symlinked_ancestor_above_the_root_does_not_refuse_the_install() {
    let base = temp_root("symlinked-ancestor");
    let real = base.join("real");
    std::fs::create_dir_all(&real).expect("real ancestor");
    let link = base.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("ancestor symlink");

    let root = link.join("repo");
    std::fs::create_dir_all(&root).expect("repository root");

    let outcome = install(&root).expect("install through a symlinked ancestor");
    assert_eq!(outcome.written.len(), TEMPLATES.len());
    assert!(root.join(".claude/rules/standards.md").is_file());
    std::fs::remove_dir_all(base).ok();
}

/// A symlinked destination inside the repository must still be refused.
#[cfg(unix)]
#[test]
fn a_symlinked_rules_directory_inside_the_root_is_still_refused() {
    let root = temp_root("symlinked-rules");
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).expect("outside directory");
    std::fs::create_dir_all(root.join(".claude")).expect("claude directory");
    std::os::unix::fs::symlink(&outside, root.join(".claude/rules")).expect("rules symlink");

    let error = install(&root).expect_err("a symlinked rules directory must be refused");
    assert!(
        error.contains("symlink"),
        "refusal must name the symlink: {error}"
    );
    assert!(!outside.join("standards.md").exists());
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn never_creates_a_claude_md_at_the_repository_root() {
    let root = temp_root("noclobber");
    std::fs::write(root.join("CLAUDE.md"), "user instructions\n").expect("existing");
    install(&root).expect("install");
    assert_eq!(
        std::fs::read_to_string(root.join("CLAUDE.md")).expect("read"),
        "user instructions\n"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn rerunning_reports_unchanged_and_writes_nothing() {
    let root = temp_root("idempotent");
    install(&root).expect("first");
    let second = install(&root).expect("second");
    assert!(second.written.is_empty());
    assert_eq!(second.unchanged.len(), TEMPLATES.len());
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn crlf_copy_of_current_template_is_unchanged() {
    let root = temp_root("crlf-current");
    let target = root.join(".claude/rules/standards.md");
    std::fs::create_dir_all(target.parent().expect("rules directory")).expect("create rules");
    let current = TEMPLATES
        .iter()
        .find(|(relative, _)| *relative == "standards.md")
        .map(|(_, contents)| contents.replace('\n', "\r\n"))
        .expect("current entry template");
    std::fs::write(target, current).expect("write CRLF current template");

    let outcome = install(&root).expect("install current template");

    assert!(outcome.unchanged.contains(&"standards.md".to_string()));
    assert!(!outcome.updated.contains(&"standards.md".to_string()));
    assert!(!outcome.kept.contains(&"standards.md".to_string()));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn crlf_copy_of_prior_release_template_is_upgraded() {
    let root = temp_root("crlf-legacy");
    let target = root.join(".claude/rules/standards.md");
    std::fs::create_dir_all(target.parent().expect("rules directory")).expect("create rules");
    let legacy = include_str!("../../../tests/fixtures/legacy-rules/v0.6.0/standards.md")
        .replace('\n', "\r\n");
    std::fs::write(target, legacy).expect("write CRLF legacy template");

    let outcome = install(&root).expect("upgrade legacy template");

    assert!(outcome.updated.contains(&"standards.md".to_string()));
    assert!(!outcome.kept.contains(&"standards.md".to_string()));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn edited_files_are_kept_rather_than_overwritten() {
    let root = temp_root("edited");
    install(&root).expect("first");
    let edited = root.join(".claude/rules/rust.md");
    std::fs::write(&edited, "---\npaths:\n  - \"**/*.rs\"\n---\n\n# Local\n").expect("edit");
    let second = install(&root).expect("second");
    assert!(second.kept.contains(&"rust.md".to_string()));
    assert!(
        std::fs::read_to_string(&edited)
            .expect("read")
            .contains("# Local")
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn exact_v05_and_v06_templates_are_updated_and_then_idempotent() {
    for release in ["v0.5.0", "v0.6.0"] {
        let root = temp_root(&format!("legacy-{release}"));
        let rules = root.join(".claude/rules");
        std::fs::create_dir_all(&rules).expect("create legacy rules");
        std::fs::write(
            rules.join("standards.md"),
            include_str!("../../../tests/fixtures/legacy-rules/v0.6.0/standards.md"),
        )
        .expect("write legacy standards");
        std::fs::write(
            rules.join("c-cpp.md"),
            include_str!("../../../tests/fixtures/legacy-rules/v0.6.0/c-cpp.md"),
        )
        .expect("write legacy C and C++ rules");

        let first = install(&root).expect("upgrade legacy templates");
        assert_eq!(first.updated.len(), 2, "{release} files must be updated");
        assert!(first.updated.contains(&"standards.md".to_string()));
        assert!(first.updated.contains(&"c-cpp.md".to_string()));
        assert!(first.kept.is_empty());
        assert!(
            std::fs::read_to_string(rules.join("standards.md"))
                .expect("read upgraded standards")
                .lines()
                .any(|line| line.trim() == ENTRY_DOCUMENT_MARKER)
        );

        let second = install(&root).expect("rerun upgraded templates");
        assert!(second.updated.is_empty());
        assert_eq!(second.unchanged.len(), TEMPLATES.len());
        std::fs::remove_dir_all(root).ok();
    }
}

#[test]
fn agents_document_inlines_every_template_without_paths_frontmatter() {
    let document = agents_document();
    for (relative, contents) in TEMPLATES {
        let body = strip_frontmatter(contents).trim_end();
        assert!(
            document.contains(body),
            "{relative} must be inlined verbatim for agents without path scoping"
        );
    }
    assert!(
        !document.contains("\npaths:\n"),
        "Claude-specific paths frontmatter must not survive concatenation"
    );
    assert!(
        document.starts_with(AGENTS_PREAMBLE),
        "the preamble must lead so the Claude-specific loading claim is corrected up front"
    );
    let entry = strip_frontmatter(TEMPLATES[0].1).trim_start();
    let first_body = document
        .split_once(&format!("\n{entry}"))
        .map(|(before, _)| before)
        .expect("the entry document must be inlined");
    assert!(
        !first_body.contains("\n# "),
        "the entry document must lead the standards, ahead of every path-scoped template"
    );
}

#[test]
fn strip_frontmatter_leaves_documents_without_a_block_untouched() {
    assert_eq!(strip_frontmatter("# Title\n"), "# Title\n");
    assert_eq!(
        strip_frontmatter("---\npaths:\n  - \"**/*.rs\"\n---\n\n# Rust\n"),
        "# Rust\n"
    );
    assert_eq!(
        strip_frontmatter("---\nunterminated\n"),
        "---\nunterminated\n",
        "an unterminated block must be kept verbatim rather than silently truncated"
    );
}

#[test]
fn agents_md_is_written_once_then_reported_unchanged() {
    let root = temp_root("agents");
    let first = install_agents_md(&root).expect("first");
    assert_eq!(first.written, vec!["AGENTS.md".to_string()]);
    let second = install_agents_md(&root).expect("second");
    assert!(second.written.is_empty());
    assert_eq!(second.unchanged, vec!["AGENTS.md".to_string()]);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn an_edited_agents_md_is_kept_rather_than_overwritten() {
    let root = temp_root("agents-edited");
    std::fs::write(root.join("AGENTS.md"), "# House rules\n").expect("existing");
    let outcome = install_agents_md(&root).expect("install");
    assert_eq!(outcome.kept, vec!["AGENTS.md".to_string()]);
    assert_eq!(
        std::fs::read_to_string(root.join("AGENTS.md")).expect("read"),
        "# House rules\n"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn agents_document_lines_matches_the_rendered_document() {
    assert_eq!(agents_document_lines(), agents_document().lines().count());
}
