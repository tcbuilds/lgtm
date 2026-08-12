use crate::discovery::{self, Workspace};
use std::collections::BTreeSet;
use std::path::Path;

use super::Status;
use super::inline_tests::{PatchIndex, inline_test_hunk_touched};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ChangeStatus {
    Changed,
    TestEvidenceExcluded,
}
impl ChangeStatus {
    fn allows_test_evidence(self) -> bool {
        self == Self::Changed
    }
}

#[derive(Clone, Copy)]
struct LanguagePack {
    name: &'static str,
    workspace_languages: &'static [&'static str],
    extensions: &'static [&'static str],
}
const LANGUAGE_PACKS: &[LanguagePack] = &[
    LanguagePack {
        name: "python",
        workspace_languages: &["python"],
        extensions: &["py"],
    },
    LanguagePack {
        name: "rust",
        workspace_languages: &["rust"],
        extensions: &["rs"],
    },
    LanguagePack {
        name: "typescript-javascript",
        workspace_languages: &["typescript"],
        extensions: &["ts", "tsx", "js", "jsx", "mjs", "cjs"],
    },
    LanguagePack {
        name: "go",
        workspace_languages: &["go"],
        extensions: &["go"],
    },
    LanguagePack {
        name: "java-kotlin",
        workspace_languages: &["jvm"],
        extensions: &["java", "kt", "kts"],
    },
    LanguagePack {
        name: "csharp",
        workspace_languages: &["csharp"],
        extensions: &["cs"],
    },
    LanguagePack {
        name: "c-cpp",
        workspace_languages: &["cpp"],
        extensions: &["c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx"],
    },
];
#[derive(Clone)]
pub(super) struct FileMatch {
    pub(super) file: String,
    language: &'static str,
    scope: String,
    basis: String,
}
pub(super) struct Association {
    pub(super) sources: Vec<FileMatch>,
    pub(super) tests: Vec<FileMatch>,
    pub(super) missing_sources: Vec<String>,
    pub(super) unverified: BTreeSet<String>,
}
#[cfg(test)]
pub(super) fn classify_changes(root: &Path, files: &BTreeSet<String>) -> Association {
    classify_changes_with_patch(root, files, &BTreeSet::new(), "")
}
pub(super) fn classify_changes_with_patch(
    root: &Path,
    files: &BTreeSet<String>,
    test_evidence_excluded: &BTreeSet<String>,
    patch: &str,
) -> Association {
    let metadata = discovery::discover(root);
    let (workspaces, metadata_error) = match metadata {
        Ok(workspaces) => (workspaces, None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    let patch_index = PatchIndex::from_patch(patch);
    let mut association = Association {
        sources: Vec::new(),
        tests: Vec::new(),
        missing_sources: Vec::new(),
        unverified: BTreeSet::new(),
    };
    for file in files {
        let status = if test_evidence_excluded.contains(file) {
            ChangeStatus::TestEvidenceExcluded
        } else {
            ChangeStatus::Changed
        };
        match classify_file(
            file,
            &workspaces,
            metadata_error.as_deref(),
            root,
            &patch_index,
        ) {
            Some(Ok(classification)) if classification.is_test => {
                if status.allows_test_evidence() {
                    association.tests.push(classification.match_info);
                }
            }
            Some(Ok(classification)) => {
                let inline_test = classification.inline_test;
                association.sources.push(classification.match_info.clone());
                if inline_test && status.allows_test_evidence() {
                    association.tests.push(classification.match_info);
                }
            }
            Some(Err(reason)) => {
                association.unverified.insert(reason);
            }
            None => {}
        }
    }
    association.missing_sources = association
        .sources
        .iter()
        .filter(|source| {
            !association
                .tests
                .iter()
                .any(|test| test.language == source.language && test.scope == source.scope)
        })
        .map(|source| source.file.clone())
        .collect();
    association
}
struct FileClassification {
    match_info: FileMatch,
    is_test: bool,
    inline_test: bool,
}
fn classify_file(
    file: &str,
    workspaces: &[Workspace],
    metadata_error: Option<&str>,
    root: &Path,
    patch: &PatchIndex,
) -> Option<Result<FileClassification, String>> {
    if is_ignored_path(file) {
        return None;
    }
    let pack = pack_for_file(file)?;
    if let Some(reason) = metadata_error {
        return Some(Err(format!(
            "{file}: workspace metadata unavailable ({reason})"
        )));
    }
    let workspace = workspace_for(file, workspaces);
    let match_info = FileMatch {
        file: file.to_string(),
        language: pack.name,
        scope: workspace_scope(workspace),
        basis: workspace_basis(pack, workspace),
    };
    let is_test = is_test_path(file, pack.name);
    Some(Ok(FileClassification {
        match_info,
        is_test,
        inline_test: pack.name == "rust" && inline_test_hunk_touched(root, file, patch),
    }))
}
fn pack_for_file(file: &str) -> Option<&'static LanguagePack> {
    let extension = Path::new(file).extension()?.to_str()?;
    LANGUAGE_PACKS.iter().find(|pack| {
        pack.extensions
            .iter()
            .any(|item| item.eq_ignore_ascii_case(extension))
    })
}
fn workspace_for<'a>(file: &str, workspaces: &'a [Workspace]) -> Option<&'a Workspace> {
    workspaces
        .iter()
        .filter(|workspace| path_in_workspace(file, &workspace.root))
        .max_by_key(|workspace| workspace.root.components().count())
}
fn path_in_workspace(file: &str, workspace: &Path) -> bool {
    let root = workspace.to_string_lossy().replace('\\', "/");
    root == "." || file == root || file.starts_with(&format!("{root}/"))
}
fn workspace_scope(workspace: Option<&Workspace>) -> String {
    workspace.map_or_else(
        || ".".to_string(),
        |workspace| workspace.root.to_string_lossy().replace('\\', "/"),
    )
}
fn workspace_basis(pack: &LanguagePack, workspace: Option<&Workspace>) -> String {
    let Some(workspace) = workspace else {
        return format!("language-pack:{};source-extension", pack.name);
    };
    if pack
        .workspace_languages
        .iter()
        .any(|language| *language == workspace.language)
    {
        format!(
            "workspace-metadata:{};language-pack:{};source-extension",
            workspace_scope(Some(workspace)),
            pack.name
        )
    } else {
        format!("language-pack:{};source-extension", pack.name)
    }
}
fn is_test_path(file: &str, language: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    let mut previous = None;
    for part in lower.split('/') {
        if is_test_directory(part) {
            return true;
        }
        if matches!(part, "integration" | "integrations") && previous.is_some_and(is_test_directory)
        {
            return true;
        }
        previous = Some(part);
    }
    let name = lower.rsplit('/').next().unwrap_or_default();
    let original_name = file.rsplit('/').next().unwrap_or_default();
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    let original_stem = original_name
        .rsplit_once('.')
        .map_or(original_name, |(stem, _)| stem);
    let prefixed = stem.starts_with("test_") || stem.starts_with("test-");
    let suffixed = ["_test", "_tests", ".test", ".spec", ".e2e", ".cy"]
        .iter()
        .any(|marker| stem.ends_with(marker));
    let language_specific = matches!(language, "java-kotlin" | "csharp")
        && (original_stem.starts_with("Test")
            || original_stem.ends_with("Test")
            || original_stem.ends_with("Tests")
            || original_stem.ends_with("Spec"));
    prefixed || suffixed || language_specific
}
fn is_test_directory(part: &str) -> bool {
    ["test", "tests", "__tests__", "spec", "specs"].contains(&part)
}
fn is_ignored_path(file: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    const IGNORED_DIRS: &[&str] = &[
        "doc",
        "docs",
        "documentation",
        "vendor",
        "third_party",
        "node_modules",
        "fixtures",
        "fixture",
        "testdata",
        "generated",
        "gen",
        "dist",
        "build",
        "target",
        "out",
        "coverage",
    ];
    if lower.split('/').any(|part| IGNORED_DIRS.contains(&part)) {
        return true;
    }
    let name = lower.rsplit('/').next().unwrap_or_default();
    const DOCUMENTATION: &str = ".md .mdx .rst .adoc .txt";
    const CONFIGURATION: &str = ".json .yaml .yml .toml .xml .ini .cfg .conf .properties .lock .mod .gradle .gradle.kts .csproj .sln makefile dockerfile cmakelists.txt";
    const GENERATED: &str =
        ".generated.rs .generated.cs .designer.cs .g.cs .pb.go _generated.go .min.js .bundle.js";
    let code_configuration = {
        let mut parts = name.rsplit('.');
        matches!(
            (parts.next(), parts.next(), parts.next()),
            (Some(_), Some("config"), Some(_))
        )
    };
    name.starts_with("readme.")
        || name.starts_with("changelog.")
        || DOCUMENTATION
            .split_whitespace()
            .any(|suffix| name.ends_with(suffix))
        || CONFIGURATION
            .split_whitespace()
            .any(|suffix| name.ends_with(suffix))
        || code_configuration
        || GENERATED
            .split_whitespace()
            .any(|suffix| name.ends_with(suffix))
}
#[cfg(test)]
pub(super) fn language_pack_policy_languages() -> BTreeSet<String> {
    LANGUAGE_PACKS
        .iter()
        .flat_map(|pack| policy_languages_for_pack(pack).iter().copied())
        .map(str::to_string)
        .collect()
}
#[cfg(test)]
fn policy_languages_for_pack(pack: &LanguagePack) -> &'static [&'static str] {
    match pack.name {
        "python" => &["python"],
        "rust" => &["rust"],
        "typescript-javascript" => &["typescript", "javascript"],
        "go" => &["go"],
        "java-kotlin" => &["java", "kotlin"],
        "csharp" => &["csharp"],
        "c-cpp" => &["c", "cpp"],
        _ => panic!("language pack is missing a policy mapping"),
    }
}
#[cfg(test)]
pub(super) fn language_pack_scope_patterns() -> BTreeSet<String> {
    LANGUAGE_PACKS
        .iter()
        .flat_map(|pack| pack.extensions.iter().copied())
        .map(|extension| format!("**/*.{extension}"))
        .collect()
}
pub(super) fn association_evidence(association: &Association) -> Vec<String> {
    let paths = |items: &[FileMatch]| {
        items
            .iter()
            .map(|item| item.file.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    let bases = association
        .sources
        .iter()
        .chain(association.tests.iter())
        .map(|item| item.basis.clone())
        .collect::<BTreeSet<_>>();
    let mut evidence = vec![
        format!("source_paths={}", paths(&association.sources)),
        format!("test_paths={}", paths(&association.tests)),
        format!(
            "missing_test_source_paths={}",
            association.missing_sources.join(",")
        ),
        format!("test_file_changed={}", !association.tests.is_empty()),
        "coverage_proven=false".to_string(),
        format!("detection_basis={}", join_or_none(&bases)),
    ];
    if !association.unverified.is_empty() {
        evidence.push(format!(
            "unverified_paths={}",
            association
                .unverified
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("|")
        ));
    }
    evidence
}
fn join_or_none(values: &BTreeSet<String>) -> String {
    match values.is_empty() {
        true => "none".to_string(),
        false => values.iter().cloned().collect::<Vec<_>>().join("|"),
    }
}
fn unverified_reason_suffix(association: &Association) -> String {
    if association.unverified.is_empty() {
        return String::new();
    }
    format!(
        " Unclassifiable changes: {}.",
        association
            .unverified
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("; ")
    )
}
pub(super) fn behavior_association_message(status: Status, association: &Association) -> String {
    match status {
        Status::NotApplicable => {
            "Source behavior test association is not applicable to this diff.".to_string()
        }
        Status::Unverified if !association.missing_sources.is_empty() => format!(
            "Review signal: no associated test file change was found for source behavior changes; this is not proof that a test is absent, and coverage is not proven. Review: {}.{}",
            association.missing_sources.join(", "),
            unverified_reason_suffix(association)
        ),
        Status::Unverified => format!(
            "Test association is unverified; coverage is not proven. Review: {}.",
            association
                .unverified
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Status::Passed => "Changed source files have plausible associated test file changes; this does not prove behavioral coverage.".to_string(),
        _ => "Source behavior test association does not require a blocking result for this diff."
            .to_string(),
    }
}
pub(super) fn bug_association_message(status: Status, association: &Association) -> String {
    match status {
        Status::NotApplicable => {
            "Regression-test association is not applicable to this diff.".to_string()
        }
        Status::Unverified if !association.missing_sources.is_empty() => format!(
            "Review signal: no associated regression-test file change was found for the bug-fix source; this is not proof that a test is absent, and coverage is not proven. Review: {}.{}",
            association.missing_sources.join(", "),
            unverified_reason_suffix(association)
        ),
        Status::Unverified => format!(
            "Bug-fix test association is unverified; coverage is not proven. Review: {}.",
            association
                .unverified
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Status::Passed => {
            "Bug-fix intent has a plausible regression test file change; coverage is not proven."
                .to_string()
        }
        _ => "Regression-test association does not require a blocking result for this diff."
            .to_string(),
    }
}
