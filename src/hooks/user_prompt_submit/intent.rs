/// Keyword-derived task intent. First matching row wins in table order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Intent {
    BugFix,
    Feature,
    Refactor,
    Infrastructure,
    Documentation,
    Unknown,
}

impl Intent {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::BugFix => "bug-fix",
            Self::Feature => "feature",
            Self::Refactor => "refactor",
            Self::Infrastructure => "infra",
            Self::Documentation => "docs",
            Self::Unknown => "unknown",
        }
    }
}

/// Deterministic taxonomy: bug terms, feature terms, refactor terms,
/// infrastructure terms, then documentation terms. Earlier categories win.
const TAXONOMY: &[(Intent, &[&str])] = &[
    (
        Intent::BugFix,
        &["bug", "fix", "broken", "regression", "error"],
    ),
    (
        Intent::Feature,
        &["feature", "add", "implement", "build", "create"],
    ),
    (
        Intent::Refactor,
        &["refactor", "cleanup", "restructure", "simplify"],
    ),
    (
        Intent::Infrastructure,
        &["infra", "deploy", "terraform", "docker", "ci"],
    ),
    (
        Intent::Documentation,
        &["docs", "documentation", "readme", "guide"],
    ),
];

pub(super) fn classify(prompt: &str) -> Intent {
    let words: Vec<_> = prompt
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '-')
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    TAXONOMY
        .iter()
        .find(|(_, keywords)| {
            keywords
                .iter()
                .any(|keyword| words.iter().any(|word| word == keyword))
        })
        .map_or(Intent::Unknown, |(intent, _)| *intent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_is_deterministic_and_precedence_ordered() {
        assert_eq!(classify("fix and add endpoint"), Intent::BugFix);
        assert_eq!(classify("implement endpoint"), Intent::Feature);
        assert_eq!(classify("refactor service"), Intent::Refactor);
        assert_eq!(classify("update terraform"), Intent::Infrastructure);
        assert_eq!(classify("write README docs"), Intent::Documentation);
        assert_eq!(classify("inspect behavior"), Intent::Unknown);
    }
}
