//! Claude's post-confirmation integrity check, not an approval-token service.
//! Native PreToolUse Ask is the authority boundary; this command only verifies
//! its exact precondition and executes one allowlisted commit without a shell.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hooks::pre_tool_use::command::parse_commit_invocation;
use crate::hooks::stop::{PreCommitGateDecision, run_pre_commit_gate_for_adapter};

const MAX_REQUEST_BYTES: usize = 32 * 1024;
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const RETRY: &str =
    "guarded commit changed or is unverified; retry the original git commit for fresh confirmation";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    version: u8,
    root: PathBuf,
    session_id: String,
    argv: Vec<String>,
    identity: String,
    executable_digest: String,
}

impl Request {
    pub(crate) fn new(
        root: &Path,
        session_id: &str,
        argv: &[String],
        identity: &str,
    ) -> Result<Self, String> {
        let request = Self {
            version: 1,
            root: root.canonicalize().map_err(|_| RETRY.to_string())?,
            session_id: session_id.to_string(),
            argv: argv.to_vec(),
            identity: identity.to_string(),
            executable_digest: executable_digest()?,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || !self.root.is_absolute()
            || self.root.canonicalize().ok().as_ref() != Some(&self.root)
            || self.session_id.is_empty()
            || self.session_id.len() > 256
            || self.session_id.chars().any(char::is_control)
            || !valid_digest(&self.identity)
            || !valid_digest(&self.executable_digest)
            || self.executable_digest != executable_digest()?
            || self.argv.len() > 64
        {
            return Err(RETRY.to_string());
        }
        let command =
            shlex::try_join(self.argv.iter().map(String::as_str)).map_err(|_| RETRY.to_string())?;
        if command.len() > MAX_REQUEST_BYTES
            || parse_commit_invocation(&command)?
                .as_ref()
                .map(|call| call.argv())
                != Some(self.argv.as_slice())
        {
            return Err(RETRY.to_string());
        }
        Ok(())
    }

    pub(crate) fn command(&self) -> Result<String, String> {
        let binary = std::env::current_exe().map_err(|_| RETRY.to_string())?;
        let binary = binary.to_str().ok_or(RETRY)?;
        let raw = serde_json::to_string(self).map_err(|_| RETRY.to_string())?;
        if raw.len() > MAX_REQUEST_BYTES {
            return Err(RETRY.to_string());
        }
        shlex::try_join([binary, "guarded-commit", "--request", &raw])
            .map_err(|_| RETRY.to_string())
    }

    pub(crate) fn verify_context(&self, root: &Path, session: Option<&str>) -> Result<(), String> {
        if root.canonicalize().ok().as_ref() != Some(&self.root)
            || session != Some(self.session_id.as_str())
        {
            return Err(RETRY.to_string());
        }
        self.validate()
    }

    pub(crate) fn revalidate(&self) -> Result<crate::adapter::PiApprovalChallenge, String> {
        self.validate()?;
        crate::hooks::pre_tool_use::validate_commit_policy(&self.root, &self.argv)?;
        match run_pre_commit_gate_for_adapter(
            &self.root,
            Some(&self.session_id),
            "claude-code",
            &self.argv,
            None,
        )? {
            PreCommitGateDecision::ClaudeApprovalRequired { identity, findings }
                if identity == self.identity =>
            {
                crate::hooks::stop::build_pi_approval_challenge(&identity, &findings)
            }
            _ => Err(RETRY.to_string()),
        }
    }
}

/// Recognize the reserved wrapper even in unsupported shell forms, then require
/// the exact shell-quoted command emitted by LGTM. No expansion is evaluated.
pub(crate) fn parse_invocation(command: &str) -> Result<Option<Request>, String> {
    if !command.contains("guarded-commit") {
        return Ok(None);
    }
    let argv = shlex::split(command).ok_or(RETRY)?;
    let binary = std::env::current_exe().map_err(|_| RETRY.to_string())?;
    let direct = argv.windows(2).any(|pair| {
        pair[1] == "guarded-commit"
            && (Path::new(&pair[0]).file_name() == binary.file_name()
                || Path::new(&pair[0]).canonicalize().ok().as_ref() == Some(&binary))
    });
    let nested_shell = argv
        .first()
        .and_then(|name| Path::new(name).file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "sh" | "bash" | "dash" | "zsh" | "fish"));
    if !direct && !nested_shell {
        return Ok(None);
    }
    if argv.len() != 4 || argv[1] != "guarded-commit" || argv[2] != "--request" {
        return Err(RETRY.to_string());
    }
    let request = parse_request(&argv[3])?;
    if request.command()? != command {
        return Err(RETRY.to_string());
    }
    Ok(Some(request))
}

fn parse_request(raw: &str) -> Result<Request, String> {
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(RETRY.to_string());
    }
    let request: Request = serde_json::from_str(raw).map_err(|_| RETRY.to_string())?;
    request.validate()?;
    Ok(request)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn executable_digest() -> Result<String, String> {
    let executable = std::env::current_exe().map_err(|_| RETRY.to_string())?;
    let file = std::fs::File::open(executable).map_err(|_| RETRY.to_string())?;
    let mut reader = file.take(MAX_BINARY_BYTES + 1);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = reader.read(&mut buffer).map_err(|_| RETRY.to_string())?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > MAX_BINARY_BYTES {
            return Err(RETRY.to_string());
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Execute only after the trusted harness has obtained native confirmation.
/// Direct agent requests for this command are also intercepted by PreToolUse.
pub fn run(raw: &str) -> ExitCode {
    match execute(raw) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("{reason}");
            ExitCode::FAILURE
        }
    }
}

fn execute(raw: &str) -> Result<(), String> {
    let request = parse_request(raw)?;
    let git = crate::checks::gitleaks::commit::resolve_binary("git")?;
    request.revalidate()?;
    if crate::checks::gitleaks::commit::resolve_binary("git")? != git {
        return Err(RETRY.to_string());
    }
    let mut command = Command::new(git);
    command.current_dir(&request.root).args(&request.argv[1..]);
    let result =
        crate::checks::gitleaks::runner::run_details_with_timeout(command, Duration::from_secs(60))
            .ok_or("guarded Git execution failed or timed out; inspect HEAD before retrying")?;
    if result.code != Some(0) || result.process_group_survived {
        return Err(format!(
            "guarded Git execution failed (exit {:?}); inspect HEAD before retrying",
            result.code
        ));
    }
    println!("Guarded commit completed.");
    Ok(())
}
