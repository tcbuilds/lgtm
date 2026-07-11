use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use lgtm::compile;

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
    Report,
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
/// Every subcommand is currently an unimplemented stub. Hook invocations must
/// fail safe: a stub must never block an agent session, so all stubs report to
/// stderr and exit with success.
fn run(command: Command) -> ExitCode {
    let name = match command {
        Command::Init => "init",
        Command::Hook { event } => return run_hook_stub(event),
        Command::Doctor => "doctor",
        Command::Compile { validate } => return run_compile(validate),
        Command::Report => "report",
    };
    report_unimplemented(name);
    ExitCode::SUCCESS
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

/// Stub for a lifecycle-event invocation. Fails safe by exiting with success.
fn run_hook_stub(event: HookEvent) -> ExitCode {
    let event_name = match event {
        HookEvent::SessionStart => "session-start",
        HookEvent::UserPromptSubmit => "user-prompt-submit",
        HookEvent::PreToolUse => "pre-tool-use",
        HookEvent::PostToolUse => "post-tool-use",
        HookEvent::Stop => "stop",
    };
    eprintln!("not yet implemented: hook {event_name}");
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
        assert!(matches!(cli.command, Command::Report));
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
