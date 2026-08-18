//! Bounded dependency-cycle detection for touched source modules.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

const MAX_MODULES: usize = 64;
const MAX_LOCATIONS: usize = MAX_MODULES;
const MAX_SOURCE_BYTES: u64 = 256 * 1024;

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    let source_files: Vec<PathBuf> = files
        .iter()
        .map(PathBuf::from)
        .filter(|path| supported(path))
        .collect();
    if source_files.is_empty() {
        return vec![result(Status::NotApplicable, Vec::new())];
    }

    let mut complete = source_files.len() <= MAX_MODULES;
    let mut graph = BTreeMap::new();
    for file in source_files.iter().take(MAX_MODULES) {
        let Some(file_imports) = imports(file) else {
            complete = false;
            graph.insert(file.clone(), Vec::new());
            continue;
        };
        graph.insert(file.clone(), file_imports);
    }

    let cycles = find_cycles(&graph);
    let status = if cycles.is_empty() {
        if complete {
            Status::Passed
        } else {
            Status::Unverified
        }
    } else {
        Status::Failed
    };
    let locations = cycles
        .into_iter()
        .take(MAX_LOCATIONS)
        .map(|path| Location {
            file: path.to_string_lossy().into_owned(),
            line: None,
        })
        .collect();
    vec![result(status, locations)]
}

fn result(status: Status, locations: Vec<Location>) -> EnforcementResult {
    let message = match status {
        Status::Failed => format!(
            "Module dependency cycle detected ({} file(s)).",
            locations.len()
        ),
        Status::Unverified => {
            "Module dependency analysis was incomplete; no deterministic cycle conclusion was possible."
                .to_string()
        }
        _ => "No deterministic module dependency cycle was found.".to_string(),
    };
    EnforcementResult {
        rule_id: "module-boundary-review".to_string(),
        severity: Severity::Error,
        status,
        message,
        locations,
        remediation: (status == Status::Failed)
            .then(|| "Break the cycle or add an adapter boundary between modules.".to_string()),
        evidence: ResultEvidence {
            check: "native.module-boundaries".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

fn supported(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("py" | "rs" | "ts" | "tsx" | "js" | "jsx")
    )
}

fn imports(path: &Path) -> Option<Vec<PathBuf>> {
    let Ok(Some(file)) = crate::fsutil::open_regular_file(path) else {
        return None;
    };

    let mut bytes = Vec::new();
    let Ok(bytes_read) = file.take(MAX_SOURCE_BYTES + 1).read_to_end(&mut bytes) else {
        return None;
    };
    if bytes_read as u64 > MAX_SOURCE_BYTES {
        return None;
    }
    let Ok(source) = String::from_utf8(bytes) else {
        return None;
    };
    Some(
        source
            .lines()
            .filter_map(|line| import_spec(line, path.extension().and_then(|value| value.to_str())))
            .filter_map(|spec| resolve_relative(path, &spec))
            .collect(),
    )
}

fn import_spec(line: &str, extension: Option<&str>) -> Option<String> {
    let trimmed = line.trim();
    if matches!(extension, Some("ts" | "tsx" | "js" | "jsx")) {
        let marker = if trimmed.starts_with("import ") {
            " from \""
        } else if trimmed.starts_with("require(\"") {
            "require(\""
        } else {
            return None;
        };
        return trimmed
            .split_once(marker)
            .and_then(|(_, rest)| rest.split_once('"').map(|(value, _)| value.to_string()))
            .filter(|value| value.starts_with('.'));
    }
    if extension == Some("rs") {
        return trimmed
            .strip_prefix("mod ")
            .and_then(|value| value.strip_suffix(';'))
            .map(|value| format!("./{value}"));
    }
    if extension == Some("py") {
        return trimmed
            .strip_prefix("from .")
            .and_then(|value| value.split_whitespace().next())
            .map(|value| format!("./{}", value.replace('.', "/")));
    }
    None
}

fn resolve_relative(file: &Path, spec: &str) -> Option<PathBuf> {
    let base = file.parent()?.join(spec);
    let candidates = [
        base.clone(),
        base.with_extension("py"),
        base.with_extension("rs"),
        base.with_extension("ts"),
        base.with_extension("js"),
        base.join("__init__.py"),
        base.join("mod.rs"),
    ];
    candidates.into_iter().find(|candidate| candidate.is_file())
}

fn find_cycles(graph: &BTreeMap<PathBuf, Vec<PathBuf>>) -> BTreeSet<PathBuf> {
    let mut cycles = BTreeSet::new();
    for node in graph.keys() {
        let mut stack = Vec::new();
        visit(node, graph, &mut stack, &mut cycles);
    }
    cycles
}

fn visit(
    node: &PathBuf,
    graph: &BTreeMap<PathBuf, Vec<PathBuf>>,
    stack: &mut Vec<PathBuf>,
    cycles: &mut BTreeSet<PathBuf>,
) {
    if let Some(index) = stack.iter().position(|item| item == node) {
        cycles.extend(stack[index..].iter().cloned());
        return;
    }
    if stack.len() >= MAX_MODULES {
        return;
    }
    stack.push(node.clone());
    if let Some(edges) = graph.get(node) {
        for edge in edges {
            if graph.contains_key(edge) {
                visit(edge, graph, stack, cycles);
            }
        }
    }
    stack.pop();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("lgtm-modules-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).expect("fixture directory");
        root
    }

    fn input_paths(paths: &[PathBuf]) -> Vec<String> {
        paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn complete_cyclic_input_fails() {
        let root = fixture_root("cycle");
        let first = root.join("first.py");
        let second = root.join("second.py");
        std::fs::write(&first, "from .second import value\n").expect("first");
        std::fs::write(&second, "from .first import value\n").expect("second");
        let results = scan(&input_paths(&[first, second]));
        assert_eq!(results[0].status, Status::Failed);
        assert_eq!(results[0].locations.len(), 2);
        assert_eq!(
            results[0].remediation.as_deref(),
            Some("Break the cycle or add an adapter boundary between modules.")
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn no_supported_files_are_not_applicable() {
        let results = scan(&["README.md".to_string(), "notes.txt".to_string()]);
        assert_eq!(results[0].status, Status::NotApplicable);
        assert!(results[0].locations.is_empty());
    }

    #[test]
    fn complete_acyclic_input_passes() {
        let root = fixture_root("acyclic");
        let source = root.join("source.py");
        std::fs::write(&source, "value = 1\n").expect("source");
        let results = scan(&input_paths(&[source]));
        assert_eq!(results[0].status, Status::Passed);
        assert!(results[0].locations.is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn supported_symlink_to_acyclic_file_is_unverified() {
        let root = fixture_root("symlink");
        let target = root.join("target.py");
        let symlink = root.join("linked.py");
        std::fs::write(&target, "value = 1\n").expect("target");
        std::os::unix::fs::symlink(&target, &symlink).expect("symlink");

        let results = scan(&input_paths(&[symlink]));
        assert_eq!(results[0].status, Status::Unverified);
        assert!(results[0].locations.is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn exactly_maximum_modules_are_passed_when_acyclic() {
        let root = fixture_root("maximum-modules");
        let mut paths = Vec::new();
        for index in 0..MAX_MODULES {
            let path = root.join(format!("module-{index:02}.py"));
            std::fs::write(&path, "value = 1\n").expect("module");
            paths.push(path);
        }

        let results = scan(&input_paths(&paths));
        assert_eq!(results[0].status, Status::Passed);
        assert!(results[0].locations.is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn invalid_utf8_applicable_input_is_unverified() {
        let root = fixture_root("invalid-utf8");
        let source = root.join("invalid.py");
        std::fs::write(&source, [0xff, 0xfe]).expect("invalid UTF-8 input");

        let results = scan(&input_paths(&[source]));
        assert_eq!(results[0].status, Status::Unverified);
        assert!(results[0].locations.is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn source_at_maximum_size_is_accepted() {
        let root = fixture_root("maximum-size");
        let source = root.join("source.py");
        std::fs::write(&source, vec![b'x'; MAX_SOURCE_BYTES as usize]).expect("maximum-size input");

        let results = scan(&input_paths(&[source]));
        assert_eq!(results[0].status, Status::Passed);
        assert!(results[0].locations.is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn unavailable_non_regular_and_oversized_inputs_are_unverified() {
        let root = fixture_root("incomplete");
        let unavailable = root.join("unavailable.py");
        let non_regular = root.join("directory.py");
        let oversized = root.join("oversized.py");
        std::fs::create_dir(&non_regular).expect("non-regular input");
        std::fs::write(&oversized, vec![b'x'; (MAX_SOURCE_BYTES as usize) + 1])
            .expect("oversized input");

        for path in [&unavailable, &non_regular, &oversized] {
            let results = scan(&[path.to_string_lossy().into_owned()]);
            assert_eq!(results[0].status, Status::Unverified);
            assert!(results[0].locations.is_empty());
        }
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn detected_cycle_takes_precedence_over_incomplete_input() {
        let root = fixture_root("cycle-incomplete");
        let first = root.join("first.py");
        let second = root.join("second.py");
        let unavailable = root.join("unavailable.py");
        std::fs::write(&first, "from .second import value\n").expect("first");
        std::fs::write(&second, "from .first import value\n").expect("second");

        let results = scan(&input_paths(&[first, second, unavailable]));
        assert_eq!(results[0].status, Status::Failed);
        assert_eq!(results[0].locations.len(), 2);
        assert!(results[0].remediation.is_some());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cycle_outside_module_limit_is_unverified() {
        let root = fixture_root("truncated-cycle");
        let mut paths = Vec::new();
        for index in 0..MAX_MODULES {
            let path = root.join(format!("filler-{index:02}.py"));
            std::fs::write(&path, "value = 1\n").expect("filler");
            paths.push(path);
        }
        let first = root.join("cycle-first.py");
        let second = root.join("cycle-second.py");
        std::fs::write(&first, "from .cycle-second import value\n").expect("first");
        std::fs::write(&second, "from .cycle-first import value\n").expect("second");
        paths.extend([first, second]);

        let results = scan(&input_paths(&paths));
        assert_eq!(results[0].status, Status::Unverified);
        assert!(results[0].locations.is_empty());
        assert!(results[0].remediation.is_none());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cycle_locations_are_bounded() {
        let root = fixture_root("bounded-cycle");
        let mut paths = Vec::new();
        for index in 0..MAX_MODULES {
            let next = (index + 1) % MAX_MODULES;
            let path = root.join(format!("module-{index:02}.py"));
            std::fs::write(&path, format!("from .module-{next:02} import value\n"))
                .expect("module");
            paths.push(path);
        }

        let results = scan(&input_paths(&paths));
        assert_eq!(results[0].status, Status::Failed);
        assert_eq!(results[0].locations.len(), MAX_LOCATIONS);
        assert_eq!(
            results[0].message,
            format!(
                "Module dependency cycle detected ({} file(s)).",
                MAX_LOCATIONS
            )
        );
        std::fs::remove_dir_all(root).ok();
    }
}
