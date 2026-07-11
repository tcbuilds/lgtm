const EXTENSIONS: &[&str] = &[
    ".py", ".rs", ".ts", ".tsx", ".js", ".jsx", ".tf", ".css", ".toml", ".json", ".md",
];

pub(super) fn likely_files(prompt: &str) -> Vec<String> {
    prompt
        .split_whitespace()
        .filter_map(clean_candidate)
        .filter(|candidate| {
            EXTENSIONS
                .iter()
                .any(|extension| candidate.ends_with(extension))
        })
        .take(1_024)
        .map(ToString::to_string)
        .collect()
}

fn clean_candidate(token: &str) -> Option<&str> {
    let candidate = token.trim_matches(|character: char| {
        matches!(
            character,
            '`' | '\'' | '"' | '(' | ')' | '[' | ']' | ',' | ':' | ';'
        )
    });
    if candidate.is_empty() || candidate.len() > 4_096 {
        return None;
    }
    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_observable_file_tokens() {
        assert_eq!(
            likely_files("fix `src/api.py`, then tests/test_api.py; ignore endpoint"),
            ["src/api.py", "tests/test_api.py"]
        );
    }
}
