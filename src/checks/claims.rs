use std::io::Read;
use std::path::Path;

use crate::checks::commands::CommandEvidence;
use crate::checks::{EnforcementResult, ResultEvidence, Status};
use crate::policy::Severity;

const MAX_TRANSCRIPT_BYTES: u64 = 2 * 1_024 * 1_024;
const MAX_CLAIMS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Claim {
    Command(String),
    TestsPassed,
}

pub fn evaluate(
    path: Option<&Path>,
    evidence: &[CommandEvidence],
    configured: &[String],
) -> EnforcementResult {
    let path = match path {
        Some(path) => path,
        None => {
            return outcome(
                Status::Unverified,
                "Transcript path is missing.",
                Vec::new(),
            );
        }
    };
    let claims = match read_claims(path, configured) {
        Ok(claims) => claims,
        Err(reason) => return outcome(Status::Unverified, &reason, Vec::new()),
    };
    if claims.is_empty() {
        return outcome(
            Status::NotApplicable,
            "No verification claims were found in the last assistant message.",
            Vec::new(),
        );
    }
    let descriptors: Vec<String> = claims.iter().map(descriptor).collect();
    if claims.iter().all(|claim| is_proven(claim, evidence)) {
        outcome(
            Status::Passed,
            "Every repository quality-gate claim has matching current Stop command evidence.",
            descriptors,
        )
    } else {
        outcome(
            Status::Failed,
            "A verification claim lacks matching current Stop command evidence with exit status 0.",
            descriptors,
        )
    }
}

fn read_claims(path: &Path, configured: &[String]) -> Result<Vec<Claim>, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("Transcript unreadable ({error})."))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Transcript metadata unavailable ({error})."))?;
    if !metadata.is_file() || metadata.len() > MAX_TRANSCRIPT_BYTES {
        return Err("Transcript is not a bounded regular file.".to_string());
    }
    let mut raw = String::new();
    file.take(MAX_TRANSCRIPT_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| format!("Transcript unreadable ({error})."))?;
    parse_claims(&raw, configured)
}

fn parse_claims(raw: &str, configured: &[String]) -> Result<Vec<Claim>, String> {
    let mut last = None;
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|_| "Transcript JSONL is malformed.".to_string())?;
        if value.get("type").and_then(|value| value.as_str()) == Some("assistant") {
            last = Some(value);
        }
    }
    let last = last.ok_or_else(|| "Transcript has no assistant entry.".to_string())?;
    let blocks = last
        .pointer("/message/content")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "Last assistant entry has malformed content.".to_string())?;
    let mut claims = Vec::new();
    for text in blocks
        .iter()
        .filter(|block| block.get("type").and_then(|value| value.as_str()) == Some("text"))
        .filter_map(|block| block.get("text").and_then(|value| value.as_str()))
    {
        extract_text_claims(text, &mut claims, configured);
        if claims.len() >= MAX_CLAIMS {
            break;
        }
    }
    claims.truncate(MAX_CLAIMS);
    Ok(claims)
}

fn extract_text_claims(text: &str, claims: &mut Vec<Claim>, configured: &[String]) {
    for line in text
        .lines()
        .filter(|line| success_line(line) && !is_non_assertive(line))
    {
        let mut parts = line.split('`');
        while let (Some(_), Some(command)) = (parts.next(), parts.next()) {
            if let Some(command) = normalize(command)
                && is_quality_gate_command(&command, configured)
            {
                claims.push(Claim::Command(command));
            }
            if claims.len() >= MAX_CLAIMS {
                return;
            }
        }
        if asserts_tests_passed(line) && !claims.contains(&Claim::TestsPassed) {
            claims.push(Claim::TestsPassed);
        }
    }
}

// An assertion that tests passed reads test-then-pass, and reads them close
// together: "42 tests passed". Scoring bare co-occurrence anywhere on a line
// scored a gate summary that lists a `test` command beside an unrelated PASS
// column, and scored a report of an earlier session's results as a claim about
// this one — neither of which the current Stop window can ever prove. Substring
// matching compounded it, since "latest" contains "test" and "bypass" contains
// "pass".
const TESTS_PASSED_WINDOW: usize = 8;

fn asserts_tests_passed(line: &str) -> bool {
    let tokens: Vec<String> = line
        .split_whitespace()
        .map(|token| {
            token
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .collect::<String>()
                .to_ascii_lowercase()
        })
        .collect();
    tokens.iter().enumerate().any(|(index, token)| {
        matches!(token.as_str(), "test" | "tests")
            && tokens
                .iter()
                .skip(index + 1)
                .take(TESTS_PASSED_WINDOW)
                .any(|later| matches!(later.as_str(), "pass" | "passed" | "passes" | "passing"))
    })
}

// Prose that describes a gate, denies having run one, or speculates about one is
// not an assertion that the gate ran. Matching on keyword presence alone scored
// such lines identically to a real claim, which made honest reporting about the
// rules unprovable and blocked Stop in a loop.
fn is_non_assertive(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "cannot",
        "can't",
        "could not",
        "couldn't",
        "did not",
        "didn't",
        "does not",
        "doesn't",
        "do not",
        "don't",
        "was not",
        "were not",
        "wasn't",
        "weren't",
        "never",
        "without",
        "unprovable",
        "unverified",
        "would ",
        "should ",
        "if ",
        "whether",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn success_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("ran ")
        || ["pass", "success", "succeed", " ran", "run:"]
            .iter()
            .any(|word| lower.contains(word))
}

fn normalize(command: &str) -> Option<String> {
    let argv = shlex::split(command.trim())?;
    (!argv.is_empty()).then(|| argv.join(" "))
}

// Only a command the repository actually configures can be proven or disproven by
// Stop evidence. Accepting any backticked token made ordinary prose — a function
// name, an identifier, a file name — into a claimed command that no evidence could
// ever satisfy, which blocked Stop permanently.
fn is_quality_gate_command(command: &str, configured: &[String]) -> bool {
    let Some(argv) = shlex::split(command) else {
        return false;
    };
    let Some(executable) = basename(argv.first().map(String::as_str)) else {
        return false;
    };
    if executable == "lgtm" {
        return argv.get(1).is_some_and(|subcommand| subcommand == "check");
    }
    configured
        .iter()
        .filter_map(|value| basename(Some(value)))
        .any(|name| name == executable)
}

fn basename(value: Option<&str>) -> Option<&str> {
    value.and_then(|value| Path::new(value).file_name().and_then(|name| name.to_str()))
}

fn is_proven(claim: &Claim, evidence: &[CommandEvidence]) -> bool {
    match claim {
        Claim::Command(command) => evidence.iter().any(|item| {
            item.exit_code == Some(0) && normalize(&item.command).as_ref() == Some(command)
        }),
        Claim::TestsPassed => evidence.iter().any(|item| {
            item.exit_code == Some(0)
                && normalize(&item.command)
                    .is_some_and(|command| command.split_whitespace().any(is_test_argument))
        }),
    }
}

fn is_test_argument(argument: &str) -> bool {
    let executable = Path::new(argument)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(argument);
    matches!(executable, "test" | "pytest" | "pytest.exe")
        || executable.ends_with("-test")
        || executable.ends_with("_test")
}

fn descriptor(claim: &Claim) -> String {
    match claim {
        Claim::Command(command) => format!(
            "command `{}`",
            command.chars().take(200).collect::<String>()
        ),
        Claim::TestsPassed => "generic tests-passed claim".to_string(),
    }
}

fn outcome(status: Status, message: &str, descriptors: Vec<String>) -> EnforcementResult {
    EnforcementResult {
        rule_id: "evidence-claims-honest".to_string(),
        status,
        severity: Severity::Error,
        message: message.to_string(),
        locations: Vec::new(),
        remediation: (status == Status::Failed).then(|| {
            "Run the claimed command successfully during Stop, or correct the claim.".to_string()
        }),
        evidence: ResultEvidence {
            check: "transcript.claims".to_string(),
            tool_version: None,
            finding_descriptions: descriptors,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript(text: &str) -> String {
        format!(
            "{{\"type\":\"user\",\"message\":{{\"content\":[]}}}}\n{{\"type\":\"assistant\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":{}}}]}}}}\n",
            serde_json::to_string(text).expect("text serializes")
        )
    }

    fn gates() -> Vec<String> {
        vec![
            "cargo".to_string(),
            "pytest".to_string(),
            "ruff".to_string(),
        ]
    }

    fn parse_claims_t(text: &str) -> Result<Vec<Claim>, String> {
        parse_claims(&transcript(text), &gates())
    }

    #[test]
    fn a_backticked_identifier_is_not_a_claimed_command() {
        let raw = transcript(
            "| 3 | prose describing a gate scored as asserting it ran | `is_non_assertive` skips them |",
        );
        assert_eq!(
            parse_claims(&raw, &gates()).expect("valid JSONL"),
            Vec::new()
        );
    }

    #[test]
    fn an_unconfigured_executable_is_not_a_claimed_command() {
        let raw = transcript("Ran `bundle exec rubocop` and it succeeded.");
        assert_eq!(
            parse_claims(&raw, &gates()).expect("valid JSONL"),
            Vec::new()
        );
    }

    #[test]
    fn describing_a_gate_is_not_a_claim_that_it_ran() {
        let raw =
            transcript("The product rule is that you cannot claim tests passed without evidence.");
        assert_eq!(
            parse_claims(&raw, &gates()).expect("valid JSONL"),
            Vec::new()
        );
    }

    #[test]
    fn denying_a_run_is_not_a_claim() {
        let raw = transcript("I did not run `cargo test`, so nothing here passed.");
        assert_eq!(
            parse_claims(&raw, &gates()).expect("valid JSONL"),
            Vec::new()
        );
    }

    #[test]
    fn speculating_about_a_gate_is_not_a_claim() {
        let raw = transcript("`cargo test` should pass once the fixture is removed.");
        assert_eq!(
            parse_claims(&raw, &gates()).expect("valid JSONL"),
            Vec::new()
        );
    }

    #[test]
    fn a_plain_assertion_is_still_captured() {
        let raw = transcript("Ran `cargo test` and it passed.");
        let claims = parse_claims(&raw, &gates()).expect("valid JSONL");
        assert!(claims.contains(&Claim::Command("cargo test".to_string())));
        assert!(claims.contains(&Claim::TestsPassed));
    }

    #[test]
    fn parses_only_last_assistant_text_claims() {
        let raw = format!(
            "{}{}",
            transcript("`cargo test` passed"),
            transcript("`cargo build` succeeded")
        );
        assert_eq!(
            parse_claims(&raw, &gates()).expect("valid JSONL"),
            vec![Claim::Command("cargo build".to_string())]
        );
    }

    #[test]
    fn matching_exit_zero_proves_claim() {
        let claims = parse_claims_t("`cargo test` passed").expect("claims");
        let evidence = vec![CommandEvidence {
            command: "cargo   test".to_string(),
            exit_code: Some(0),
            duration_ms: 1,
            argv: Vec::new(),
            cwd: None,
            workspace_id: None,
            config_digest: None,
            touched_files_digest: None,
            policy_version: None,
            binary_version: None,
            started_at_ms: None,
            finished_at_ms: None,
        }];
        assert!(claims.iter().all(|claim| is_proven(claim, &evidence)));
    }

    #[test]
    fn fabricated_command_claim_without_matching_evidence_is_rejected() {
        let claim = Claim::Command("cargo test".to_string());
        let evidence = vec![CommandEvidence {
            command: "cargo test".to_string(),
            exit_code: Some(1),
            duration_ms: 1,
            argv: Vec::new(),
            cwd: None,
            workspace_id: None,
            config_digest: None,
            touched_files_digest: None,
            policy_version: None,
            binary_version: None,
            started_at_ms: None,
            finished_at_ms: None,
        }];
        assert!(!is_proven(&claim, &evidence));
        assert!(!is_proven(&claim, &[]));
    }

    #[test]
    fn generic_test_summary_requires_successful_test_command() {
        let claims = parse_claims_t("Tests: 42 passed").expect("claims");
        assert_eq!(claims, vec![Claim::TestsPassed]);
        let evidence = vec![CommandEvidence {
            command: "cargo test".to_string(),
            exit_code: Some(0),
            duration_ms: 1,
            argv: Vec::new(),
            cwd: None,
            workspace_id: None,
            config_digest: None,
            touched_files_digest: None,
            policy_version: None,
            binary_version: None,
            started_at_ms: None,
            finished_at_ms: None,
        }];
        assert!(claims.iter().all(|claim| is_proven(claim, &evidence)));
    }

    #[test]
    fn ignores_operational_lgtm_claims() {
        let claims = parse_claims_t("`lgtm doctor` passed; `lgtm hook pre-tool-use` succeeded.")
            .expect("claims");
        assert!(claims.is_empty());
    }

    #[test]
    fn keeps_lgtm_full_check_as_a_quality_claim() {
        let claims = parse_claims_t("`lgtm check --tier full` passed").expect("claims");
        assert_eq!(
            claims,
            vec![Claim::Command("lgtm check --tier full".to_string())]
        );
    }

    #[test]
    fn unrelated_command_with_test_substring_does_not_prove_tests() {
        let evidence = vec![CommandEvidence {
            command: "echo contest".to_string(),
            exit_code: Some(0),
            duration_ms: 1,
            argv: Vec::new(),
            cwd: None,
            workspace_id: None,
            config_digest: None,
            touched_files_digest: None,
            policy_version: None,
            binary_version: None,
            started_at_ms: None,
            finished_at_ms: None,
        }];
        assert!(!is_proven(&Claim::TestsPassed, &evidence));
    }

    #[test]
    fn reporting_a_prior_run_is_not_a_claim_that_it_ran_now() {
        let raw = transcript(
            "**Gates at handoff (all PASS @ `6aea7a1`):** fmt, clippy, test (269 lib + 24 suites), `compile --validate` (71 rules).",
        );
        assert_eq!(
            parse_claims(&raw, &gates()).expect("valid JSONL"),
            Vec::new()
        );
    }

    #[test]
    fn a_pass_word_before_the_test_word_is_not_a_claim() {
        let raw = transcript("All gates PASS: fmt, clippy, test, build.");
        assert_eq!(
            parse_claims(&raw, &gates()).expect("valid JSONL"),
            Vec::new()
        );
    }

    #[test]
    fn substrings_of_test_and_pass_are_not_a_claim() {
        let raw = transcript("The latest bypass is documented and passes review.");
        assert_eq!(
            parse_claims(&raw, &gates()).expect("valid JSONL"),
            Vec::new()
        );
    }

    #[test]
    fn a_pass_word_at_the_window_edge_is_still_a_claim() {
        let raw = transcript("The 413 tests one two three four five six seven passed.");
        assert_eq!(
            parse_claims(&raw, &gates()).expect("valid JSONL"),
            vec![Claim::TestsPassed]
        );
    }

    #[test]
    fn a_pass_word_past_the_window_edge_is_not_a_claim() {
        let raw = transcript("The 413 tests one two three four five six seven eight passed.");
        assert_eq!(
            parse_claims(&raw, &gates()).expect("valid JSONL"),
            Vec::new()
        );
    }

    #[test]
    fn malformed_jsonl_is_unverified_input() {
        assert!(parse_claims("{not json\n", &gates()).is_err());
    }
}
