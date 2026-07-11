#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Fast,
    Targeted,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    PostToolUse,
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Secrets,
    Diff,
    Ruff,
    RelatedTests,
    Mypy,
    Semgrep,
    RepositoryCommands,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Supported,
    NotConfigured,
}

const FAST: [Check; 3] = [Check::Secrets, Check::Diff, Check::Ruff];
const TARGETED: [Check; 3] = [Check::RelatedTests, Check::Mypy, Check::Semgrep];
const FULL: [Check; 5] = [
    Check::Secrets,
    Check::Diff,
    Check::Ruff,
    Check::Semgrep,
    Check::RepositoryCommands,
];

pub fn checks(tier: Tier) -> &'static [Check] {
    match tier {
        Tier::Fast => &FAST,
        Tier::Targeted => &TARGETED,
        Tier::Full => &FULL,
    }
}

pub fn for_hook(hook: Hook) -> Tier {
    match hook {
        Hook::PostToolUse => Tier::Fast,
        Hook::Stop => Tier::Full,
    }
}

pub fn targeted_availability(check: Check) -> Availability {
    match check {
        Check::Semgrep => Availability::Supported,
        Check::RelatedTests | Check::Mypy => Availability::NotConfigured,
        _ => Availability::Supported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_have_stable_cost_order() {
        assert_eq!(
            checks(Tier::Fast),
            [Check::Secrets, Check::Diff, Check::Ruff]
        );
        assert_eq!(
            checks(Tier::Targeted),
            [Check::RelatedTests, Check::Mypy, Check::Semgrep]
        );
        assert_eq!(
            checks(Tier::Full),
            [
                Check::Secrets,
                Check::Diff,
                Check::Ruff,
                Check::Semgrep,
                Check::RepositoryCommands
            ]
        );
    }

    #[test]
    fn hooks_select_fast_and_full_tiers() {
        assert_eq!(for_hook(Hook::PostToolUse), Tier::Fast);
        assert_eq!(for_hook(Hook::Stop), Tier::Full);
    }

    #[test]
    fn unsupported_targeted_checks_are_explicit() {
        assert_eq!(
            targeted_availability(Check::RelatedTests),
            Availability::NotConfigured
        );
        assert_eq!(
            targeted_availability(Check::Mypy),
            Availability::NotConfigured
        );
        assert_eq!(
            targeted_availability(Check::Semgrep),
            Availability::Supported
        );
    }
}
