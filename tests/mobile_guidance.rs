mod common;

use common::TempRepo;
use lgtm::init::install_rules;
use lgtm::path_injection::{PathInjectionRequest, select_rule_bodies};
use lgtm::policy::frontmatter::{RULE_DOCUMENT_SOURCES, body, load_rule_files};
use sha2::{Digest, Sha256};

const MOBILE_DOCUMENTS: [&str; 3] = ["mobile-ui.md", "ios-ui.md", "android-ui.md"];

// Keep the scope matrix together so platform bleed is visible beside positive cases.
#[test]
fn mobile_guidance_is_injected_only_for_mobile_paths_and_the_matching_platform() {
    let cases = [
        ("ios/Views/Home.swift", [true, true, false]),
        ("apps/shop/ios/Views/Home.swift", [true, true, false]),
        ("iosApp/ContentView.swift", [true, true, false]),
        ("ios/Main.storyboard", [true, true, false]),
        ("ios/Legacy/ViewController.m", [true, true, false]),
        ("src/Home.ios.tsx", [true, true, false]),
        ("Home.ios.jsx", [true, true, false]),
        ("android/app/src/main/Home.kt", [true, false, true]),
        ("apps/shop/android/res/layout/main.xml", [true, false, true]),
        ("android/app/src/main/Home.java", [true, false, true]),
        ("src/Home.android.tsx", [true, false, true]),
        ("Home.android.js", [true, false, true]),
        ("mobile/src/Home.tsx", [true, false, false]),
        ("apps/mobile/lib/home.dart", [true, false, false]),
        ("react-native/src/Home.jsx", [true, false, false]),
        ("Home.native.tsx", [true, false, false]),
        ("web/src/Home.tsx", [false, false, false]),
        ("web/mobile.css", [false, false, false]),
        ("backend/src/Main.kt", [false, false, false]),
        ("server/Sources/main.swift", [false, false, false]),
        ("desktop/ContentView.swift", [false, false, false]),
        ("desktop/lib/main.dart", [false, false, false]),
        ("desktop/src/Main.kt", [false, false, false]),
        ("src/Home.tsx", [false, false, false]),
        ("lib/main.dart", [false, false, false]),
        ("ios/README.md", [false, false, false]),
        ("android/build.gradle.kts", [false, false, false]),
        ("mobile/server.py", [false, false, false]),
    ];
    for (path, expected) in cases {
        let result = select_rule_bodies(&PathInjectionRequest::new(vec![path.into()], None));
        assert!(
            result.diagnostics.is_empty(),
            "{path}: {:?}",
            result.diagnostics
        );
        for (name, should_match) in MOBILE_DOCUMENTS.into_iter().zip(expected) {
            let selected = result.bodies.iter().find(|document| {
                document.source_path == format!("templates/claude-rules/rules/{name}")
            });
            assert_eq!(selected.is_some(), should_match, "{name} for {path}");
            if let Some(selected) = selected {
                assert!(!selected.body.contains("\npaths:\n"));
                assert!(selected.body.contains("Apply only"));
            }
        }
    }
}

#[test]
fn installed_mobile_guidance_matches_embedded_bodies_and_refreshes_local_edits() {
    let repo = TempRepo::new();
    let first = install_rules(repo.path()).expect("fresh install");
    for name in MOBILE_DOCUMENTS {
        assert!(first.written.iter().any(|path| path == name));
        let source_path = format!("templates/claude-rules/rules/{name}");
        let (_, embedded) = RULE_DOCUMENT_SOURCES
            .iter()
            .find(|(path, _)| *path == source_path)
            .expect("embedded mobile document");
        let installed = repo.read(&format!(".claude/rules/{name}"));
        assert_eq!(installed, *embedded, "Claude/Pi source parity: {name}");
        assert!(
            load_rule_files(&[(&source_path, embedded)])
                .expect("valid guidance")
                .is_empty()
        );
        assert!(body(embedded).expect("body").contains("Apply only"));
    }
    let second = install_rules(repo.path()).expect("repeat install");
    assert!(second.written.is_empty());
    for name in MOBILE_DOCUMENTS {
        assert!(second.unchanged.iter().any(|path| path == name));
        repo.write(
            &format!(".claude/rules/{name}"),
            "# Local mobile guidance\n",
        );
    }
    let third = install_rules(repo.path()).expect("refresh edits");
    for name in MOBILE_DOCUMENTS {
        assert!(third.updated.iter().any(|path| path == name));
        let source_path = format!("templates/claude-rules/rules/{name}");
        let (_, embedded) = RULE_DOCUMENT_SOURCES
            .iter()
            .find(|(path, _)| *path == source_path)
            .expect("embedded mobile document");
        assert_eq!(repo.read(&format!(".claude/rules/{name}")), *embedded);
        assert_eq!(
            repo.read(&format!(
                ".claude/rules/{name}.{:x}.bak",
                Sha256::digest(b"# Local mobile guidance\n")
            )),
            "# Local mobile guidance\n"
        );
    }
}

#[test]
fn pre_mobile_codex_document_upgrades_and_then_stays_unchanged() {
    let repo = TempRepo::new();
    lgtm::init::install_agents(repo.path()).expect("current Codex install");
    let current = repo.read("AGENTS.md");
    let mut previous = current.clone();
    for name in MOBILE_DOCUMENTS {
        let source_path = format!("templates/claude-rules/rules/{name}");
        let (_, contents) = RULE_DOCUMENT_SOURCES
            .iter()
            .find(|(path, _)| *path == source_path)
            .expect("embedded mobile document");
        let section = format!(
            "\n---\n\n{}\n",
            body(contents).expect("body").trim_start().trim_end()
        );
        assert!(previous.contains(&section), "missing Codex section {name}");
        previous = previous.replace(&section, "");
    }
    repo.write("AGENTS.md", &previous);
    let upgrade = lgtm::init::install_agents(repo.path()).expect("upgrade previous Codex document");
    assert_eq!(upgrade.updated, ["AGENTS.md"]);
    assert_eq!(repo.read("AGENTS.md"), current);
    let repeat = lgtm::init::install_agents(repo.path()).expect("repeat Codex install");
    assert_eq!(repeat.unchanged, ["AGENTS.md"]);
}
