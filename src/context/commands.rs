use std::collections::BTreeMap;

use crate::detect::Detection;

pub(super) fn repository_commands(detection: &Detection) -> BTreeMap<String, Vec<String>> {
    let mut grouped = BTreeMap::new();
    for (_, commands) in &detection.required_commands {
        for command in commands {
            let category = command_category(command);
            grouped
                .entry(category.to_string())
                .or_insert_with(Vec::new)
                .push(command.clone());
        }
    }
    grouped
}

fn command_category(command: &str) -> &'static str {
    match command.split_whitespace().next().unwrap_or_default() {
        "ruff" if command.contains("format") => "format",
        "ruff" => "lint",
        "mypy" | "pyright" => "types",
        "pytest" => "tests",
        "cargo" if command.contains(" fmt") => "format",
        "cargo" if command.contains(" clippy") => "lint",
        "cargo" if command.contains(" test") => "tests",
        _ => "checks",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_known_commands_by_purpose() {
        assert_eq!(command_category("ruff check ."), "lint");
        assert_eq!(command_category("mypy --strict src"), "types");
        assert_eq!(command_category("pytest"), "tests");
        assert_eq!(command_category("cargo fmt --check"), "format");
        assert_eq!(command_category("cargo clippy"), "lint");
        assert_eq!(command_category("cargo test"), "tests");
    }
}
