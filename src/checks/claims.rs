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

pub fn evaluate(path: Option<&Path>, evidence: &[CommandEvidence]) -> EnforcementResult {
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
    let claims = match read_claims(path) {
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
            "Every verification claim has matching current Stop command evidence.",
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

fn read_claims(path: &Path) -> Result<Vec<Claim>, String> {
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
    parse_claims(&raw)
}

fn parse_claims(raw: &str) -> Result<Vec<Claim>, String> {
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
        extract_text_claims(text, &mut claims);
        if claims.len() >= MAX_CLAIMS {
            break;
        }
    }
    claims.truncate(MAX_CLAIMS);
    Ok(claims)
}

fn extract_text_claims(text: &str, claims: &mut Vec<Claim>) {
    for line in text.lines().filter(|line| success_line(line)) {
        let mut parts = line.split('`');
        while let (Some(_), Some(command)) = (parts.next(), parts.next()) {
            if let Some(command) = normalize(command) {
                claims.push(Claim::Command(command));
            }
            if claims.len() >= MAX_CLAIMS {
                return;
            }
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("test") && lower.contains("pass") && !claims.contains(&Claim::TestsPassed)
        {
            claims.push(Claim::TestsPassed);
        }
    }
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

    #[test]
    fn parses_only_last_assistant_text_claims() {
        let raw = format!(
            "{}{}",
            transcript("`cargo test` passed"),
            transcript("`cargo build` succeeded")
        );
        assert_eq!(
            parse_claims(&raw).expect("valid JSONL"),
            vec![Claim::Command("cargo build".to_string())]
        );
    }

    #[test]
    fn matching_exit_zero_proves_claim() {
        let claims = parse_claims(&transcript("`cargo test` passed")).expect("claims");
        let evidence = vec![CommandEvidence {
            command: "cargo   test".to_string(),
            exit_code: Some(0),
            duration_ms: 1,
            argv: Vec::new(),
            cwd: None,
        }];
        assert!(claims.iter().all(|claim| is_proven(claim, &evidence)));
    }

    #[test]
    fn nonzero_or_missing_evidence_disproves_claim() {
        let claim = Claim::Command("cargo test".to_string());
        let evidence = vec![CommandEvidence {
            command: "cargo test".to_string(),
            exit_code: Some(1),
            duration_ms: 1,
            argv: Vec::new(),
            cwd: None,
        }];
        assert!(!is_proven(&claim, &evidence));
        assert!(!is_proven(&claim, &[]));
    }

    #[test]
    fn generic_test_summary_requires_successful_test_command() {
        let claims = parse_claims(&transcript("Tests: 42 passed")).expect("claims");
        assert_eq!(claims, vec![Claim::TestsPassed]);
        let evidence = vec![CommandEvidence {
            command: "cargo test".to_string(),
            exit_code: Some(0),
            duration_ms: 1,
            argv: Vec::new(),
            cwd: None,
        }];
        assert!(claims.iter().all(|claim| is_proven(claim, &evidence)));
    }

    #[test]
    fn unrelated_command_with_test_substring_does_not_prove_tests() {
        let evidence = vec![CommandEvidence {
            command: "echo contest".to_string(),
            exit_code: Some(0),
            duration_ms: 1,
            argv: Vec::new(),
            cwd: None,
        }];
        assert!(!is_proven(&Claim::TestsPassed, &evidence));
    }

    #[test]
    fn malformed_jsonl_is_unverified_input() {
        assert!(parse_claims("{not json\n").is_err());
    }
}
