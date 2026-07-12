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
    Init {
        /// Preview detected workspaces and planned files without writing.
        #[arg(long)]
        dry_run: bool,
        /// Convert an existing V1 config to structured V2 with a backup.
        #[arg(long)]
        migrate_config: bool,
        /// Allow medium-confidence fallback commands during normal init.
        #[arg(long)]
        accept_guesses: bool,
    },
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
    /// Inspect the embedded policy registry.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Validate and inspect repository configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Validate the repository config without writing.
    Validate,
    /// Print the repository config as formatted JSON.
    Show,
    /// Report stale workspace paths and missing command binaries.
    Doctor,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// List every embedded rule.
    List {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show one embedded rule in detail.
    Show {
        /// Stable rule identifier.
        rule_id: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Explain rule selection and preview the compact packet for a file.
    Explain {
        /// Repository-relative file path used as the task observable.
        #[arg(long)]
        file: PathBuf,
        /// Optional intent signal added to deterministic rule selection.
        #[arg(long)]
        intent: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Export the embedded policy bundle and checksums.
    Export {
        /// Destination directory for the exported bundle.
        #[arg(long)]
        output: PathBuf,
        /// Replace an existing destination directory.
        #[arg(long)]
        force: bool,
    },
    /// Generate a supported-standards Markdown matrix from the ledger.
    Docs {
        /// Destination Markdown file.
        #[arg(long)]
        output: PathBuf,
        /// Check for drift without writing.
        #[arg(long)]
        check: bool,
    },
    /// Show standards coverage status.
    Coverage {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
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
        Command::Init {
            dry_run,
            migrate_config,
            accept_guesses,
        } => run_init(dry_run, migrate_config, accept_guesses),
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
        Command::Policy { command } => run_policy(command),
        Command::Config { command } => run_config(command),
    }
}

fn run_policy(command: PolicyCommand) -> ExitCode {
    let rules = match lgtm::policy::load_embedded_registry() {
        Ok(rules) => rules,
        Err(error) => {
            eprintln!("policy failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    match command {
        PolicyCommand::List { json } => {
            if json {
                return write_json(&rules);
            }
            println!("ID\tLEVEL\tSEVERITY\tMODE\tMECHANISM\tCONFIDENCE\tSTAGE\tCATEGORY\tTITLE");
            for rule in rules {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    rule.id,
                    rule.level,
                    rule.severity,
                    rule.enforcement.mode,
                    rule.mechanism,
                    rule.confidence,
                    rule.enforcement_stage,
                    rule.category,
                    rule.title
                );
            }
            ExitCode::SUCCESS
        }
        PolicyCommand::Show { rule_id, json } => {
            let Some(rule) = rules.into_iter().find(|rule| rule.id == rule_id) else {
                eprintln!("policy failed: unknown rule `{rule_id}`");
                return ExitCode::FAILURE;
            };
            if json {
                return write_json(&rule);
            }
            println!("id: {}", rule.id);
            println!("title: {}", rule.title);
            println!("description: {}", rule.description);
            println!("level: {}", rule.level);
            println!("severity: {}", rule.severity);
            println!("category: {}", rule.category);
            println!("enforcement: {}", rule.enforcement.mode);
            println!("mechanism: {}", rule.mechanism);
            println!("confidence: {}", rule.confidence);
            println!("enforcement stage: {}", rule.enforcement_stage);
            println!("checks: {}", rule.enforcement.checks.join(", "));
            println!("languages: {}", rule.applies_to.languages.join(", "));
            println!("domains: {}", rule.applies_to.domains.join(", "));
            println!("files: {}", rule.applies_to.file_patterns.join(", "));
            println!("instruction: {}", rule.instruction);
            println!("examples: {}", rule.examples.join(" | "));
            println!("limitations: {}", rule.limitations.join(" | "));
            println!("evidence: {}", rule.evidence.required.join(", "));
            println!("overridable: {}", rule.overridable);
            println!("references: {}", rule.references.join(", "));
            ExitCode::SUCCESS
        }
        PolicyCommand::Explain { file, intent, json } => {
            run_policy_explain(&rules, &file, intent.as_deref(), json)
        }
        PolicyCommand::Export { output, force } => {
            match lgtm::policy::export::run(&output, force) {
                Ok(message) => {
                    println!("{message}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("policy export failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        PolicyCommand::Docs { output, check } => match lgtm::policy::docs::write(&output, check) {
            Ok(()) => {
                println!(
                    "{} {}",
                    if check {
                        "generated docs clean:"
                    } else {
                        "generated docs:"
                    },
                    output.display()
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("policy docs failed: {error}");
                ExitCode::FAILURE
            }
        },
        PolicyCommand::Coverage { json } => {
            let report = match lgtm::policy::coverage::report() {
                Ok(report) => report,
                Err(error) => {
                    eprintln!("policy coverage failed: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if json {
                return write_json(&report);
            }
            let mut counts = [0_usize; 3];
            println!("SECTION\tSTATUS\tMECHANISM\tRULES\tNOTES");
            for section in report.ledger.sections {
                let index = match section.status {
                    lgtm::policy::coverage::CoverageStatus::Covered => 0,
                    lgtm::policy::coverage::CoverageStatus::Partial => 1,
                    lgtm::policy::coverage::CoverageStatus::Unsupported => 2,
                };
                counts[index] += 1;
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    section.heading,
                    section.status,
                    section.mechanism,
                    section.rule_ids.join(","),
                    section.notes
                );
            }
            println!(
                "summary: covered={} partial={} unsupported={}",
                counts[0], counts[1], counts[2]
            );
            ExitCode::SUCCESS
        }
    }
}

fn run_policy_explain(
    rules: &[lgtm::policy::Rule],
    file: &Path,
    intent: Option<&str>,
    json: bool,
) -> ExitCode {
    let root = match std::env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("policy explain failed: resolve cwd ({error})");
            return ExitCode::FAILURE;
        }
    };
    let relative = if file.is_absolute() {
        match file.strip_prefix(&root) {
            Ok(path) => path.to_path_buf(),
            Err(_) => {
                eprintln!("policy explain failed: file must be inside the repository");
                return ExitCode::FAILURE;
            }
        }
    } else {
        file.to_path_buf()
    };
    let relative = relative.to_string_lossy().replace('\\', "/");
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.split('/').any(|part| part == "..")
    {
        eprintln!("policy explain failed: file must be a safe repository-relative path");
        return ExitCode::FAILURE;
    }
    let mut context = lgtm::context::build(&root, std::slice::from_ref(&relative), "");
    if let Some(intent) = intent.filter(|intent| !intent.trim().is_empty()) {
        context.risk_signals.push(intent.to_string());
        context.risk_signals.sort();
        context.risk_signals.dedup();
    }
    let decisions = lgtm::select::explain_rules(&context, rules, lgtm::policy::ChangeType::Modify);
    let selected: Vec<_> =
        lgtm::select::select_rules(&context, rules, lgtm::policy::ChangeType::Modify);
    let compiled = lgtm::compile::compile_selected(&selected, &context.files_touched);
    if json {
        return write_json(&serde_json::json!({
            "file": relative,
            "intent": intent,
            "context": context,
            "decisions": decisions,
            "packet": compiled.packet,
            "plan": compiled.plan,
        }));
    }
    println!("file: {relative}");
    println!("languages: {}", context.languages.join(", "));
    println!("domains: {}", context.domains.join(", "));
    println!("signals: {}", context.risk_signals.join(", "));
    println!("selected rules:");
    for decision in decisions.iter().filter(|decision| decision.selected) {
        println!("  + {} ({})", decision.rule_id, decision.reason);
    }
    println!("rejected rules:");
    for decision in decisions.iter().filter(|decision| !decision.selected) {
        println!("  - {} ({})", decision.rule_id, decision.reason);
    }
    println!("\npacket:\n{}", compiled.packet);
    ExitCode::SUCCESS
}

fn run_config(command: ConfigCommand) -> ExitCode {
    let root = match std::env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("config failed: resolve cwd ({error})");
            return ExitCode::FAILURE;
        }
    };
    let path = root.join(".lgtm/config.json");
    let raw = lgtm::fsutil::read_optional_bounded(&path, 256 * 1024);
    if raw.trim().is_empty() {
        eprintln!("config failed: .lgtm/config.json is missing or empty");
        return ExitCode::FAILURE;
    }
    let value: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("config failed: invalid JSON ({error})");
            return ExitCode::FAILURE;
        }
    };
    match command {
        ConfigCommand::Validate => {
            if value.get("version").and_then(serde_json::Value::as_str)
                == Some(lgtm::config_v2::VERSION)
            {
                match lgtm::config_v2::parse(&value) {
                    Ok(_) => println!("config valid: V2"),
                    Err(error) => {
                        eprintln!("config invalid: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            } else if let Err(error) = lgtm::checks::commands::load(&root) {
                eprintln!("config invalid: {error}");
                return ExitCode::FAILURE;
            } else {
                println!("config valid: V1 compatibility");
            }
            ExitCode::SUCCESS
        }
        ConfigCommand::Show => write_json(&value),
        ConfigCommand::Doctor => {
            if value.get("version").and_then(serde_json::Value::as_str)
                != Some(lgtm::config_v2::VERSION)
            {
                println!("config doctor: V1 compatibility mode; run `lgtm init --migrate-config`");
                return ExitCode::SUCCESS;
            }
            let config = match lgtm::config_v2::parse(&value) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("config doctor failed: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let mut findings = 0_usize;
            for workspace in &config.workspaces {
                let workspace_root = root.join(&workspace.root);
                if !workspace_root.is_dir() {
                    findings += 1;
                    println!(
                        "STALE workspace={} root={}",
                        workspace.id,
                        workspace.root.display()
                    );
                }
                for command in &workspace.commands {
                    if !command_available(&command.argv[0], &workspace_root) {
                        findings += 1;
                        println!(
                            "MISSING workspace={} command={}",
                            workspace.id, command.argv[0]
                        );
                    }
                }
            }
            if findings == 0 {
                println!("config doctor: clean");
            } else {
                println!(
                    "config doctor: {findings} finding(s); propose repair with `lgtm init --dry-run`"
                );
            }
            ExitCode::SUCCESS
        }
    }
}

fn command_available(command: &str, cwd: &Path) -> bool {
    let path = Path::new(command);
    if path.components().count() > 1 {
        return cwd.join(path).is_file() || path.is_file();
    }
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|directory| directory.join(command).is_file())
    })
}

fn write_json<T: serde::Serialize>(value: &T) -> ExitCode {
    match serde_json::to_string_pretty(value) {
        Ok(rendered) => {
            println!("{rendered}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("policy failed: serialize output ({error})");
            ExitCode::FAILURE
        }
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
fn run_init(dry_run: bool, migrate_config: bool, accept_guesses: bool) -> ExitCode {
    let result = if migrate_config {
        init::migrate_config(Path::new("."), dry_run)
    } else if dry_run {
        init::preview(Path::new("."))
    } else {
        init::run_with_options(Path::new("."), accept_guesses)
    };
    match result {
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
    println!("  workspaces: {}", summary.workspaces.len());
    for workspace in &summary.workspaces {
        println!(
            "    {} ({}) cwd={}",
            workspace.id,
            workspace.language,
            workspace.root.display()
        );
        for command in &workspace.commands {
            println!(
                "      {} [{}] confidence={}",
                command.argv.join(" "),
                command.purpose,
                command.confidence
            );
        }
    }
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
    match lgtm::checks::commands::load(Path::new(".")) {
        Ok(settings) if !settings.structured.is_empty() => {
            println!(
                "config V2: ready ({} structured commands)",
                settings.structured.len()
            );
            for command in settings.structured {
                println!(
                    "  {} (cwd={})",
                    command.argv.join(" "),
                    command.cwd.display()
                );
            }
        }
        Ok(_) => println!("config gates: legacy or none detected"),
        Err(reason) => println!("config gates: invalid ({reason})"),
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
        assert!(matches!(
            cli.command,
            Command::Init {
                dry_run: false,
                migrate_config: false,
                accept_guesses: false
            }
        ));
    }

    #[test]
    fn parses_doctor_subcommand() {
        let cli = Cli::try_parse_from(["lgtm", "doctor"]).expect("doctor should parse");
        assert!(matches!(cli.command, Command::Doctor));
    }

    #[test]
    fn parses_config_subcommands() {
        let cli =
            Cli::try_parse_from(["lgtm", "config", "doctor"]).expect("config doctor should parse");
        assert!(matches!(cli.command, Command::Config { .. }));
    }

    #[test]
    fn parses_report_subcommand() {
        let cli = Cli::try_parse_from(["lgtm", "report"]).expect("report should parse");
        assert!(matches!(cli.command, Command::Report { .. }));
    }

    #[test]
    fn parses_policy_commands() {
        let list = Cli::try_parse_from(["lgtm", "policy", "list", "--json"])
            .expect("policy list should parse");
        assert!(matches!(
            list.command,
            Command::Policy {
                command: PolicyCommand::List { json: true }
            }
        ));
        let show = Cli::try_parse_from(["lgtm", "policy", "show", "external-call-timeout"])
            .expect("policy show should parse");
        assert!(matches!(
            show.command,
            Command::Policy {
                command: PolicyCommand::Show { ref rule_id, json: false }
            } if rule_id == "external-call-timeout"
        ));
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
