use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use std::path::{Path, PathBuf};

use lgtm::compile;
use lgtm::hooks::post_tool_use;
use lgtm::hooks::pre_tool_use;
use lgtm::hooks::session_start;
use lgtm::hooks::stop;
use lgtm::hooks::user_prompt_submit;
use lgtm::init;

/// Agent-neutral policy compiler and enforcement runtime.
#[derive(Debug, Parser)]
#[command(name = "lgtm", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Register hooks and scaffold config in the current repository.
    Init,
    /// Run the policy runtime for a single agent lifecycle event.
    Hook {
        /// Lifecycle event that triggered this invocation.
        event: HookEvent,
    },
    /// Report missing wrapped tools and their install commands.
    Doctor,
    /// Compile the policy registry into task-specific outputs.
    Compile {
        /// Validate the embedded registry against its schema instead of compiling.
        #[arg(long)]
        validate: bool,
    },
    /// Summarize evidence records for completed tasks.
    Report {
        #[arg(long)]
        evidence: Option<PathBuf>,
        #[arg(long)]
        task: Option<String>,
    },
    /// Create or replace an audited, expiring waiver for a non-protected rule.
    Waive {
        #[arg(long)]
        rule: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        expires: String,
    },
    /// Check for or install a newer LGTM release.
    Update {
        /// Report the available version without replacing the binary.
        #[arg(long)]
        check: bool,
        /// Install a specific v-prefixed release instead of the latest.
        #[arg(long)]
        version: Option<String>,
    },
}

/// The five native agent lifecycle events wired by the Claude Code adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum HookEvent {
    SessionStart,
    UserPromptSubmit,
    PreToolUse,
    PostToolUse,
    Stop,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    run(cli.command)
}

/// Dispatch a parsed command to its handler.
///
/// Implemented commands dispatch to their handlers. Remaining stubs report to
/// stderr and exit successfully so unfinished hooks never wedge an agent session.
fn run(command: Command) -> ExitCode {
    match command {
        Command::Init => run_init(),
        Command::Hook { event } => run_hook(event),
        Command::Doctor => run_doctor(),
        Command::Compile { validate } => run_compile(validate),
        Command::Report { evidence, task } => run_report(evidence, task),
        Command::Waive {
            rule,
            reason,
            owner,
            expires,
        } => run_waive(&rule, &reason, &owner, &expires),
        Command::Update { check, version } => run_update(check, version.as_deref()),
    }
}

fn run_update(check: bool, version: Option<&str>) -> ExitCode {
    match lgtm::update::run(check, version) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("update failed: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn run_waive(rule: &str, reason: &str, owner: &str, expires: &str) -> ExitCode {
    let root = match std::env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("waive failed: resolve cwd ({error})");
            return ExitCode::FAILURE;
        }
    };
    match lgtm::policy::waivers::create(&root, rule, reason, owner, expires) {
        Ok(()) => {
            println!("waiver recorded for {rule} through {expires}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("waive failed: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn run_report(evidence: Option<PathBuf>, task: Option<String>) -> ExitCode {
    let path = evidence.unwrap_or_else(|| PathBuf::from(".lgtm/evidence/evidence.jsonl"));
    let stdout = io::stdout();
    match lgtm::report::render(&path, task.as_deref(), &mut stdout.lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("report failed: {reason}");
            ExitCode::FAILURE
        }
    }
}

/// Handle `lgtm compile`.
///
/// With `--validate`, load the embedded registry, validate it against the rule
/// schema, deserialize it, and print a summary table on stdout — exiting 0 when
/// valid and non-zero with precise errors when not. Without the flag, the full
/// compile pipeline is not yet implemented.
fn run_compile(validate: bool) -> ExitCode {
    if !validate {
        report_unimplemented("compile");
        return ExitCode::SUCCESS;
    }
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let result = compile::validate_registry(&mut handle);
    compile_exit_code(result, &mut handle)
}

/// Map a validation result to a process exit code, reporting failures to stderr.
///
/// On failure the stdout handle is flushed before the error is written so any
/// partial summary is not interleaved with the error line. The error message is
/// printed with a single trailing newline. The two flush results are
/// deliberately ignored: nothing actionable remains if flushing stderr fails
/// while the process is already exiting non-zero.
fn compile_exit_code(
    result: Result<Vec<lgtm::policy::Rule>, compile::CompileError>,
    stdout: &mut impl Write,
) -> ExitCode {
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = stdout.flush();
            eprintln!("registry validation failed: {error}");
            let _ = io::stderr().flush();
            ExitCode::FAILURE
        }
    }
}

/// Handle `lgtm init`.
///
/// Scaffolds repo-local config and merges Claude Code hook entries into the
/// current working directory, then prints a concise report to stdout. On
/// failure the precise cause is written to stderr and the process exits
/// non-zero without partially reporting success.
fn run_init() -> ExitCode {
    match init::run(Path::new(".")) {
        Ok(summary) => {
            report_init_summary(&summary);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("init failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Print the human-readable init report to stdout.
fn report_init_summary(summary: &init::InitSummary) {
    let languages = if summary.detection.languages.is_empty() {
        "none".to_string()
    } else {
        summary.detection.languages.join(", ")
    };
    println!("lgtm init complete");
    println!("  git repo: {}", summary.detection.is_git_repo);
    println!("  languages: {languages}");
    for (language, commands) in &summary.detection.required_commands {
        println!("  commands ({language}): {}", commands.join(", "));
    }
    if summary.files_written.is_empty() {
        println!("  files: already up to date");
    } else {
        println!("  files: {}", summary.files_written.join(", "));
    }
    for note in &summary.notes {
        println!("  note: {note}");
    }
}

/// Dispatch a lifecycle-event invocation to its handler.
///
/// Implemented hooks read their payload from stdin and write their agent-facing
/// response to stdout. Stop is the deliberate exception to the usual fail-safe
/// success exit: it returns 2 when a rerun confirms an unresolved MUST failure.
fn run_hook(event: HookEvent) -> ExitCode {
    match event {
        HookEvent::SessionStart => {
            let stdin = io::stdin();
            let stdout = io::stdout();
            session_start::run(&mut stdin.lock(), &mut stdout.lock())
        }
        HookEvent::UserPromptSubmit => {
            let stdin = io::stdin();
            let stdout = io::stdout();
            user_prompt_submit::run(&mut stdin.lock(), &mut stdout.lock())
        }
        HookEvent::PreToolUse => {
            let stdin = io::stdin();
            let stdout = io::stdout();
            pre_tool_use::run(&mut stdin.lock(), &mut stdout.lock())
        }
        HookEvent::PostToolUse => {
            let stdin = io::stdin();
            let stdout = io::stdout();
            post_tool_use::run(&mut stdin.lock(), &mut stdout.lock())
        }
        HookEvent::Stop => {
            let stdin = io::stdin();
            let stdout = io::stdout();
            stop::run(&mut stdin.lock(), &mut stdout.lock())
        }
    }
}

/// Report whether the wrapped MVP tool is ready and how to install it.
fn run_doctor() -> ExitCode {
    match lgtm::checks::gitleaks::installed_version() {
        Some(version) => println!("gitleaks: ready ({version})"),
        None => {
            println!("gitleaks: MISSING");
            println!("  Install: https://github.com/gitleaks/gitleaks#installing");
            println!("  macOS: brew install gitleaks");
            println!("  Go: go install github.com/zricethezav/gitleaks/v8@latest");
        }
    }
    match lgtm::checks::ruff::installed_version() {
        Some(version) => println!("ruff: ready ({version})"),
        None => {
            println!("ruff: MISSING");
            println!("  Install: uv tool install ruff");
            println!("  Alternative: pipx install ruff");
        }
    }
    match lgtm::checks::semgrep::installed_version() {
        Some(version) => println!("semgrep: ready ({version})"),
        None => {
            println!("semgrep: MISSING");
            println!("  Install: uv tool install semgrep");
        }
    }
    ExitCode::SUCCESS
}

/// Emit a stable "not yet implemented" line to stderr for a subcommand.
fn report_unimplemented(subcommand: &str) {
    eprintln!("not yet implemented: {subcommand}");
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::CommandFactory;
    use clap::error::ErrorKind;

    #[test]
    fn version_flag_requests_version_display() {
        let error = Cli::try_parse_from(["lgtm", "--version"])
            .expect_err("--version should short-circuit parsing");
        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_init_subcommand() {
        let cli = Cli::try_parse_from(["lgtm", "init"]).expect("init should parse");
        assert!(matches!(cli.command, Command::Init));
    }

    #[test]
    fn parses_doctor_subcommand() {
        let cli = Cli::try_parse_from(["lgtm", "doctor"]).expect("doctor should parse");
        assert!(matches!(cli.command, Command::Doctor));
    }

    #[test]
    fn parses_report_subcommand() {
        let cli = Cli::try_parse_from(["lgtm", "report"]).expect("report should parse");
        assert!(matches!(cli.command, Command::Report { .. }));
    }

    #[test]
    fn parses_update_options() {
        let cli = Cli::try_parse_from(["lgtm", "update", "--check", "--version", "v1.2.3"])
            .expect("update should parse");
        assert!(matches!(
            cli.command,
            Command::Update {
                check: true,
                version: Some(ref version)
            } if version == "v1.2.3"
        ));
    }

    #[test]
    fn parses_compile_without_validate() {
        let cli = Cli::try_parse_from(["lgtm", "compile"]).expect("compile should parse");
        assert!(matches!(cli.command, Command::Compile { validate: false }));
    }

    #[test]
    fn parses_compile_with_validate_flag() {
        let cli =
            Cli::try_parse_from(["lgtm", "compile", "--validate"]).expect("compile should parse");
        assert!(matches!(cli.command, Command::Compile { validate: true }));
    }

    #[test]
    fn parses_every_hook_event() {
        let cases = [
            ("session-start", HookEvent::SessionStart),
            ("user-prompt-submit", HookEvent::UserPromptSubmit),
            ("pre-tool-use", HookEvent::PreToolUse),
            ("post-tool-use", HookEvent::PostToolUse),
            ("stop", HookEvent::Stop),
        ];
        for (arg, expected) in cases {
            let cli = Cli::try_parse_from(["lgtm", "hook", arg]).expect("hook event should parse");
            match cli.command {
                Command::Hook { event } => assert_eq!(event, expected),
                other => panic!("expected hook command, got {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_unknown_hook_event() {
        let result = Cli::try_parse_from(["lgtm", "hook", "not-a-real-event"]);
        assert!(result.is_err(), "unknown hook event must be rejected");
    }

    #[test]
    fn compile_exit_code_is_success_when_validation_ok() {
        let mut sink = Vec::new();
        let code = compile_exit_code(Ok(Vec::new()), &mut sink);
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "a successful validation must exit with success"
        );
    }

    #[test]
    fn compile_exit_code_is_failure_when_validation_fails() {
        let failure = compile::CompileError::Write(io::Error::other("write failed"));
        let mut sink = Vec::new();
        let code = compile_exit_code(Err(failure), &mut sink);
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::FAILURE),
            "a failing validation must exit with failure"
        );
    }
}
