use std::path::Path;

#[test]
fn manifest_covers_supported_language_families_and_safety_cases() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/universal");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("manifest.json")).expect("fixture manifest"),
    )
    .expect("valid fixture manifest");
    let languages = manifest["languages"].as_array().expect("languages");
    for language in [
        "python",
        "typescript",
        "rust",
        "go",
        "shell",
        "terraform",
        "jvm",
        "csharp",
        "cpp",
        "sql",
    ] {
        assert!(
            languages.iter().any(|item| item == language),
            "missing {language}"
        );
    }
    for case in [
        "root-clean",
        "python-monorepo",
        "typescript-app",
        "rust-cli",
        "mixed-repo",
        "monorepo-mixed",
        "missing-tool",
        "malformed-config",
        "legacy-config",
        "windows-path",
        "oversize-input",
    ] {
        assert!(root.join(case).exists(), "missing fixture {case}");
    }
}
