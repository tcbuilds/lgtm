//! Bounded dependency-cycle detection for touched source modules.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

const MAX_MODULES: usize = 64;
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
    let mut graph = BTreeMap::new();
    for file in source_files.iter().take(MAX_MODULES) {
        graph.insert(file.clone(), imports(file));
    }
    let cycles = find_cycles(&graph);
    if cycles.is_empty() {
        vec![result(Status::Passed, Vec::new())]
    } else {
        let locations = cycles
            .into_iter()
            .map(|path| Location {
                file: path.to_string_lossy().into_owned(),
                line: None,
            })
            .collect();
        vec![result(Status::Failed, locations)]
    }
}

fn result(status: Status, locations: Vec<Location>) -> EnforcementResult {
    EnforcementResult {
        rule_id: "module-boundary-review".to_string(),
        severity: Severity::Error,
        status,
        message: if status == Status::Failed {
            format!(
                "Module dependency cycle detected ({} file(s)).",
                locations.len()
            )
        } else {
            "No deterministic module dependency cycle was found.".to_string()
        },
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

fn imports(path: &Path) -> Vec<PathBuf> {
    let Ok(metadata) = std::fs::metadata(path) else {
        return Vec::new();
    };
    if !metadata.is_file() || metadata.len() > MAX_SOURCE_BYTES {
        return Vec::new();
    }
    let Ok(source) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    source
        .lines()
        .filter_map(|line| import_spec(line, path.extension().and_then(|value| value.to_str())))
        .filter_map(|spec| resolve_relative(path, &spec))
        .collect()
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

    #[test]
    fn detects_relative_python_cycle() {
        let root = std::env::temp_dir().join(format!("lgtm-modules-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("fixture directory");
        let first = root.join("first.py");
        let second = root.join("second.py");
        std::fs::write(&first, "from .second import value\n").expect("first");
        std::fs::write(&second, "from .first import value\n").expect("second");
        let results = scan(&[
            first.to_string_lossy().into_owned(),
            second.to_string_lossy().into_owned(),
        ]);
        assert_eq!(results[0].status, Status::Failed);
        assert_eq!(results[0].locations.len(), 2);
        std::fs::remove_dir_all(root).ok();
    }
}
