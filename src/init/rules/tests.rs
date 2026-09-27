use super::*;

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::super::template_digests::{
    CURRENT_GENERATED_DOCUMENT_DIGESTS, CURRENT_TEMPLATE_DIGESTS, LEGACY_TEMPLATE_DIGESTS,
    current_template_digest,
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
fn standalone_carriage_returns_are_not_treated_as_line_ending_equivalent() {
    assert!(same_template_line_endings(b"one\r\ntwo", b"one\ntwo"));
    assert!(!same_template_line_endings(b"one\rtwo", b"one\ntwo"));
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
fn edited_named_rule_is_replaced_with_current_frontmatter_and_backed_up() {
    let root = temp_root("edited");
    install(&root).expect("first");
    let edited = root.join(".claude/rules/rust.md");
    let local = "---\ndescription: Local Rust rules\npaths:\n  - \"**/*.rs\"\n---\n\n# Local\n";
    std::fs::write(&edited, local).expect("edit");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&edited, std::fs::Permissions::from_mode(0o600))
            .expect("restrictive rule mode");
    }
    let backup = edited.with_file_name(format!(
        "rust.md.{:x}.bak",
        Sha256::digest(local.as_bytes())
    ));

    let second = install(&root).expect("replace edited rule");
    assert!(second.updated.contains(&"rust.md".to_string()));
    assert_eq!(
        std::fs::read(&edited).expect("read current"),
        TEMPLATES
            .iter()
            .find(|(path, _)| *path == "rust.md")
            .expect("rust template")
            .1
            .as_bytes()
    );
    assert_eq!(
        std::fs::read(&backup).expect("read backup"),
        local.as_bytes()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&backup)
                .expect("backup metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let third = install(&root).expect("second replacement");
    assert!(third.updated.is_empty());
    assert!(third.unchanged.contains(&"rust.md".to_string()));
    assert_eq!(
        std::fs::read(&backup).expect("read backup"),
        local.as_bytes()
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn successive_different_rule_edits_preserve_both_content_addressed_backups() {
    let root = temp_root("successive-backups");
    install(&root).expect("first");
    let target = root.join(".claude/rules/rust.md");
    let first = "# First local rule\n";
    let second = "# Second local rule\n";
    std::fs::write(&target, first).expect("first edit");
    install(&root).expect("first refresh");
    std::fs::write(&target, second).expect("second edit");
    install(&root).expect("second refresh");

    let first_backup = target.with_file_name(format!(
        "rust.md.{:x}.bak",
        Sha256::digest(first.as_bytes())
    ));
    let second_backup = target.with_file_name(format!(
        "rust.md.{:x}.bak",
        Sha256::digest(second.as_bytes())
    ));
    assert_eq!(
        std::fs::read(first_backup).expect("first backup"),
        first.as_bytes()
    );
    assert_eq!(
        std::fs::read(second_backup).expect("second backup"),
        second.as_bytes()
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn custom_rule_filename_is_preserved_when_shipped_rules_are_refreshed() {
    let root = temp_root("custom-file");
    let custom = root.join(".claude/rules/custom.md");
    std::fs::create_dir_all(custom.parent().expect("rules directory")).expect("create rules");
    std::fs::write(&custom, "# Custom rule\n").expect("write custom rule");

    install(&root).expect("install shipped rules");

    assert_eq!(
        std::fs::read(&custom).expect("read custom"),
        b"# Custom rule\n"
    );
    assert!(!custom.with_file_name("custom.md.bak").exists());
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn differing_rule_backup_blocks_a_replacement_without_clobbering_either_file() {
    let root = temp_root("backup-collision");
    install(&root).expect("first");
    let target = root.join(".claude/rules/rust.md");
    let local = b"# Local rule\n";
    let backup = root.join(format!(
        ".claude/rules/rust.md.{:x}.bak",
        Sha256::digest(local)
    ));
    std::fs::write(&target, local).expect("edit rule");
    std::fs::write(&backup, "# Previous backup\n").expect("write foreign backup");

    let error = install(&root).expect_err("differing backup must refuse replacement");

    assert!(error.contains("existing rule backup differs"));
    assert_eq!(
        std::fs::read(&target).expect("read target"),
        b"# Local rule\n"
    );
    assert_eq!(
        std::fs::read(&backup).expect("read backup"),
        b"# Previous backup\n"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn pi_refreshes_shipped_rules_but_preserves_custom_agents_guidance() {
    let root = temp_root("pi-refresh");
    let target = root.join(".claude/rules/rust.md");
    std::fs::create_dir_all(target.parent().expect("rules directory")).expect("create rules");
    let old_rule = b"---\ndescription: Old Rust\n---\n# Local\n";
    std::fs::write(&target, old_rule).expect("old rule");
    std::fs::write(root.join("AGENTS.md"), "# House rules\n").expect("house rules");

    let outcome = install_pi_guidance(&root).expect("Pi guidance install");

    assert!(outcome.updated.contains(&"rust.md".to_string()));
    let agents = std::fs::read_to_string(root.join("AGENTS.md")).expect("read agents");
    assert!(agents.starts_with(
        "# House rules\n\n<!-- lgtm-pi-guidance:start -->\n<!-- lgtm-entry-document: standards-v1 -->\n# Engineering Standards"
    ));
    assert!(agents.ends_with("<!-- lgtm-pi-guidance:end -->\n"));
    assert_eq!(
        std::fs::read(&target).expect("read current"),
        TEMPLATES
            .iter()
            .find(|(path, _)| *path == "rust.md")
            .expect("rust template")
            .1
            .as_bytes()
    );
    assert_eq!(
        std::fs::read(target.with_file_name(format!("rust.md.{:x}.bak", Sha256::digest(old_rule))))
            .expect("read backup"),
        old_rule
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
