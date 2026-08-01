use super::*;

fn temp_root(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("lgtm-rules-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp root");
    root
}

#[test]
fn every_template_declares_paths_except_the_entry_document() {
    for (relative, contents) in TEMPLATES {
        if *relative == "standards.md" {
            assert!(
                !contents.starts_with("---"),
                "the entry document must load every session, so it carries no paths frontmatter"
            );
            continue;
        }
        assert!(
            contents.starts_with("---\npaths:\n"),
            "{relative} must declare a paths glob so it loads only for matching files"
        );
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
