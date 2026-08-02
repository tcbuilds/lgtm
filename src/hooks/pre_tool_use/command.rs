//! Match a shell command against the prohibited-command policy.
//!
//! A policy entry names an executable, the flags that make it destructive, and
//! the leading operands that must be present. Comparing raw argv token prefixes
//! cannot see that `-rf` and `-r -f` are the same flags, that `--recursive`
//! names `-r`, or that a leading `sudo` shifts every token by one, so this
//! module reduces both the policy entry and the candidate command to a
//! [`CommandShape`] — executable, flag set, ordered operands — and compares
//! those instead.
//!
//! Matching is deliberately narrow in the other direction: a policy entry only
//! matches when every flag it names is present, so `git clean -fdx` does not
//! match bare `git clean -fd`, and an unrecognized long option keeps its own
//! spelling, so `--force-with-lease` never collapses into `--force`.
//!
//! Both sides are shaped by the same code, so a policy entry written in long
//! form and one written in short form produce identical verdicts.

use std::collections::BTreeSet;

/// Flag spellings that name the same option.
///
/// Agreement is checked pairwise between a rule flag and a command flag rather
/// than by rewriting either into a canonical token, because the classes overlap
/// on purpose. `-r` and `-R` sit in separate classes: they are synonyms for
/// `rm` but distinct options for tools like `ls`, so treating them as
/// interchangeable would risk a false block. `--recursive` belongs to both, so
/// a long-form policy entry matches either short spelling and a short-form
/// entry matches the long spelling, without making the two short spellings
/// equivalent to each other.
///
/// A spelling absent from every class agrees only with itself, which is what
/// keeps `--force-with-lease` from ever satisfying a `--force` rule.
const EQUIVALENT_FLAG_SPELLINGS: &[&[&str]] = &[
    &["-r", "--recursive"],
    &["-R", "--recursive"],
    &["-f", "--force"],
];

/// Short options that are boolean for the executables the default policy names,
/// listed so a clustered token can be split without guessing.
///
/// `-rf` is two flags and `-ofoo` is one flag with an attached value, and the
/// two are indistinguishable without the executable's own option table.
/// Splitting blindly invents a `-f` inside `git push -ofoo` and falsely blocks
/// a legitimate push, so a multi-character token is only split when every
/// character is a known boolean option for that executable. An executable
/// absent from this table keeps such tokens whole, which degrades to literal
/// token matching rather than to a wrong answer.
///
/// Options that take a value are deliberately excluded: `git push -o`,
/// `git clean -e`, and `shred -n` must never be read as cluster members.
const CLUSTERABLE_SHORT_FLAGS: &[(&str, &str)] = &[
    ("rm", "dfiIrRvP"),
    ("chmod", "cfvR"),
    ("git", "dfinquvxX"),
    ("shred", "fuvz"),
];

/// Leading wrappers that run another command with modified privilege or
/// environment, paired with the wrapper options that consume the following
/// token.
///
/// The option lists exist so an option value is not mistaken for the wrapped
/// executable: without `-u` listed, `sudo -u root rm -rf /` would be matched as
/// a command named `root`. Boolean options are deliberately absent; a wrong
/// guess in either direction only shifts which token is read as the executable,
/// which costs coverage rather than producing a false block.
const COMMAND_WRAPPERS: &[(&str, &[&str])] = &[
    (
        "sudo",
        &[
            "-C",
            "-D",
            "-g",
            "-h",
            "-p",
            "-R",
            "-r",
            "-T",
            "-t",
            "-U",
            "-u",
            "--chdir",
            "--chroot",
            "--close-from",
            "--command-timeout",
            "--group",
            "--host",
            "--other-user",
            "--prompt",
            "--role",
            "--type",
            "--user",
        ],
    ),
    ("doas", &["-a", "-C", "-u"]),
    (
        "env",
        &["-C", "-S", "-u", "--chdir", "--split-string", "--unset"],
    ),
    ("command", &[]),
    ("nice", &["-n", "--adjustment"]),
    (
        "ionice",
        &[
            "-c",
            "-n",
            "-p",
            "-P",
            "-u",
            "--class",
            "--classdata",
            "--pgid",
            "--pid",
            "--uid",
        ],
    ),
];

/// Maximum wrapper layers peeled from one command.
///
/// Real commands nest at most a wrapper or two; the cap keeps a hostile argv
/// from turning matching into unbounded work.
const MAX_WRAPPER_DEPTH: usize = 8;

/// A command reduced to the parts the policy compares.
#[derive(Debug)]
struct CommandShape<'a> {
    /// The executable as written, with no path or alias resolution.
    executable: &'a str,
    /// Every flag the command carries, splittable short clusters expanded and
    /// long options reduced to their name. Spellings are kept as written and
    /// reconciled at compare time by [`flags_agree`].
    flags: BTreeSet<String>,
    /// Non-flag arguments in the order they were written, including anything
    /// after an end-of-options `--`.
    operands: Vec<&'a str>,
}

/// A command that the prohibited-command policy blocks.
#[derive(Debug)]
pub(super) struct ProhibitedMatch {
    /// The wrapper tokens peeled off before matching, empty when the command
    /// matched as typed.
    wrapper: Vec<String>,
}

impl ProhibitedMatch {
    /// Deny text naming the policy and, when a wrapper was peeled, the tokens
    /// that were looked through, so a user whose command does not literally
    /// start with a policy entry can still see why it was blocked.
    ///
    /// Assignment values are redacted first: this string is handed to the agent
    /// and written into the local evidence record, and `env API_TOKEN=... rm
    /// -rf x` would otherwise persist the secret.
    pub(super) fn reason(&self) -> String {
        if self.wrapper.is_empty() {
            return "command matches prohibited_commands policy".to_string();
        }
        let wrapper: Vec<String> = self
            .wrapper
            .iter()
            .map(|token| redact_assignment_value(token))
            .collect();
        format!(
            "command matches prohibited_commands policy after the wrapper prefix `{}`",
            wrapper.join(" ")
        )
    }
}

/// Replace the value of an assignment or option token, keeping its name so the
/// reason still shows what was passed. Bare options without a value remain
/// visible so the wrapper behavior stays explainable.
fn redact_assignment_value(token: &str) -> String {
    match token.split_once('=') {
        Some((name, _)) => format!("{name}=<redacted>"),
        None => token.to_string(),
    }
}

/// Match `argv` against every policy entry, returning the first block.
///
/// An empty policy entry, or one whose executable is empty, is skipped rather
/// than treated as a wildcard.
pub(super) fn find_match(argv: &[String], rules: &[Vec<String>]) -> Option<ProhibitedMatch> {
    let (wrapper, wrapped) = split_wrappers(argv);
    let command = shape(wrapped)?;
    rules
        .iter()
        .filter_map(|rule| shape(rule))
        .any(|rule| covers(&rule, &command))
        .then(|| ProhibitedMatch {
            wrapper: wrapper.to_vec(),
        })
}

/// True when the policy entry `rule` blocks `command`.
///
/// The executable must be identical, every flag the rule names must be present
/// in any order or spelling, and the rule's operands must lead the command's
/// operands so `chmod -R 777` does not block `chmod -R 755`.
fn covers(rule: &CommandShape<'_>, command: &CommandShape<'_>) -> bool {
    rule.executable == command.executable
        && rule.flags.iter().all(|required| {
            command
                .flags
                .iter()
                .any(|present| flags_agree(required, present))
        })
        && command.operands.starts_with(&rule.operands)
}

/// True when two flag spellings name the same option.
fn flags_agree(left: &str, right: &str) -> bool {
    left == right
        || EQUIVALENT_FLAG_SPELLINGS
            .iter()
            .any(|class| class.contains(&left) && class.contains(&right))
}

/// Reduce an argv list to its executable, flag set, and operands.
///
/// Returns `None` for an empty argv or an empty executable so a malformed
/// policy entry cannot match every command.
fn shape(argv: &[String]) -> Option<CommandShape<'_>> {
    let (executable, arguments) = argv.split_first()?;
    if executable.is_empty() {
        return None;
    }
    let mut flags = BTreeSet::new();
    let mut operands = Vec::new();
    let mut options_ended = false;
    for argument in arguments {
        if options_ended {
            operands.push(argument.as_str());
            continue;
        }
        if argument == "--" {
            options_ended = true;
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let name = long.split_once('=').map_or(long, |(name, _)| name);
            flags.insert(format!("--{name}"));
            continue;
        }
        match argument.strip_prefix('-') {
            Some(cluster) if !cluster.is_empty() => {
                for flag in expand_cluster(executable, cluster, argument) {
                    flags.insert(flag);
                }
            }
            _ => operands.push(argument.as_str()),
        }
    }
    Some(CommandShape {
        executable,
        flags,
        operands,
    })
}

/// Split a short-option token into the flags it names.
///
/// A single-character token is unambiguous. A longer one is only split when
/// every character is a known boolean short option for this executable, because
/// `-rf` and `-ofoo` are otherwise indistinguishable and splitting the latter
/// would invent a `-f` that falsely blocks a legitimate `git push -ofoo`. An
/// unsplittable token is kept whole so it can still match a policy entry that
/// spells it the same way.
fn expand_cluster(executable: &str, cluster: &str, token: &str) -> Vec<String> {
    if cluster.chars().count() == 1 {
        return vec![token.to_string()];
    }
    let clusterable = CLUSTERABLE_SHORT_FLAGS
        .iter()
        .find(|(name, _)| *name == executable)
        .map_or("", |(_, flags)| *flags);
    if cluster.chars().all(|flag| clusterable.contains(flag)) {
        return cluster.chars().map(|flag| format!("-{flag}")).collect();
    }
    vec![token.to_string()]
}

/// Split `argv` into the leading privilege and environment wrappers and the
/// command they wrap.
fn split_wrappers(argv: &[String]) -> (&[String], &[String]) {
    let mut consumed = 0;
    for _ in 0..MAX_WRAPPER_DEPTH {
        let Some(length) = peel_wrapper(&argv[consumed..]) else {
            break;
        };
        consumed += length;
    }
    argv.split_at(consumed)
}

/// Count the leading tokens of one wrapper invocation: the wrapper name, its
/// own options and option values, and any `NAME=VALUE` assignments.
///
/// Returns `None` when the first token is not a wrapper, or when peeling would
/// consume the whole argv. A bare `sudo` is still the command the user ran, and
/// leaving nothing behind would hand matching an empty argv.
///
/// Any token starting with `-` counts as a wrapper option, including a lone `-`,
/// which is how `env - command` asks for an empty environment. The scan is
/// bounded by the argument count so it terminates even if a branch fails to
/// advance.
fn peel_wrapper(argv: &[String]) -> Option<usize> {
    let (name, arguments) = argv.split_first()?;
    let options = COMMAND_WRAPPERS
        .iter()
        .find(|(wrapper, _)| wrapper == name)
        .map(|(_, options)| *options)?;
    let mut index = 0;
    for _ in 0..arguments.len() {
        let Some(argument) = arguments.get(index).map(String::as_str) else {
            break;
        };
        if argument == "--" {
            index += 1;
            break;
        }
        if argument.starts_with('-') {
            index += 1;
            if !argument.contains('=') && options.contains(&argument) {
                index += 1;
            }
            continue;
        }
        if !is_assignment(argument) {
            break;
        }
        index += 1;
    }
    if index >= arguments.len() {
        return None;
    }
    Some(index + 1)
}

/// True when a token is a `NAME=VALUE` assignment a wrapper applies to the
/// environment rather than the command it runs.
///
/// The name is not validated beyond being non-empty, because `sudo` and `env`
/// both accept names this code has no reason to second-guess. Misreading an
/// executable whose own name contains `=` only shifts which token is matched,
/// which costs coverage rather than producing a false block.
fn is_assignment(token: &str) -> bool {
    matches!(token.split_once('='), Some((name, _)) if !name.is_empty())
}

#[cfg(test)]
mod tests;
