//! Adversarial coverage for prohibited-command matching.
//!
//! The tables assert against [`DEFAULT_PROHIBITED_COMMANDS`], the policy a
//! fresh repository is actually seeded with, so a change to the shipped rules
//! cannot silently drift away from what these tests claim to prove.

use std::path::{Path, PathBuf};

use super::*;
use crate::init::execpolicy::DEFAULT_PROHIBITED_COMMANDS;

/// The shipped default policy in the shape the hook reads from disk, so the
/// tables below assert against the rules a fresh repository actually gets.
fn default_policy() -> Vec<Vec<String>> {
    DEFAULT_PROHIBITED_COMMANDS
        .iter()
        .map(|rule| rule.iter().map(|token| (*token).to_string()).collect())
        .collect()
}

fn argv(command: &str) -> Vec<String> {
    shlex::split(command).expect("test command parses")
}

fn matched(command: &str) -> Option<ProhibitedMatch> {
    find_match(&argv(command), &default_policy())
}

fn is_denied(command: &str) -> bool {
    matched(command).is_some()
}

/// Build a policy from commands written the way a user would author them.
fn policy(entries: &[&str]) -> Vec<Vec<String>> {
    entries.iter().map(|entry| argv(entry)).collect()
}

fn is_denied_by(rules: &[Vec<String>], command: &str) -> bool {
    find_match(&argv(command), rules).is_some()
}

/// The deny text for a command, or an empty string when it is allowed.
fn deny_reason(command: &str) -> String {
    matched(command)
        .map(|found| found.reason())
        .unwrap_or_default()
}

#[test]
fn wrapper_prefixes_do_not_bypass_the_policy() {
    for command in [
        "sudo rm -rf /tmp/x",
        "env rm -rf /tmp/x",
        "sudo -u root rm -rf /tmp/x",
        "sudo --user=root rm -rf /tmp/x",
        "sudo -- rm -rf /tmp/x",
        "doas rm -rf /tmp/x",
        "command rm -rf /tmp/x",
        "nice -n 19 rm -rf /tmp/x",
        "ionice -c 3 rm -rf /tmp/x",
        "sudo env rm -rf /tmp/x",
        "env FOO=1 rm -rf /tmp/x",
        "sudo git push --force origin main",
        "sudo -i rm -rf /tmp/x",
        "env -i rm -rf /tmp/x",
        "env - rm -rf /tmp/x",
    ] {
        assert!(is_denied(command), "{command} must be denied");
    }
    for command in [
        "sudo systemctl restart x",
        "env FOO=1 cargo test",
        "sudo",
        "sudo -u root",
        "env",
        "nice -n 19 cargo test",
        "sudo rm build/artifact.o",
        "sudo git push --force-with-lease origin main",
    ] {
        assert!(!is_denied(command), "{command} must be allowed");
    }
}

#[test]
fn stripping_never_removes_the_final_executable() {
    for command in ["sudo", "env", "sudo -u root", "nice -n 19", "sudo --"] {
        let tokens = argv(command);
        let (wrapper, wrapped) = split_wrappers(&tokens);
        assert!(
            wrapper.is_empty(),
            "{command} has no wrapped command to peel toward"
        );
        assert_eq!(
            wrapped, tokens,
            "{command} must be matched as the command it is"
        );
        assert_eq!(
            shape(wrapped)
                .expect("a wrapper alone is still a command")
                .executable,
            tokens[0],
            "{command} must keep its executable"
        );
    }
}

#[test]
fn an_empty_policy_entry_never_matches() {
    let rules = vec![Vec::new(), vec![String::new(), "-rf".to_string()]];
    assert!(find_match(&argv("rm -rf /"), &rules).is_none());
    assert!(find_match(&argv("sudo rm -rf /"), &rules).is_none());
}

#[test]
fn flag_order_and_spelling_do_not_change_the_verdict() {
    for command in [
        "rm -rf /tmp/x",
        "rm -fr /tmp/x",
        "rm -r -f /tmp/x",
        "rm -f -r /tmp/x",
        "rm --recursive --force /tmp/x",
        "rm -r --force /tmp/x",
        "rm --force -r /tmp/x",
        "rm -f --recursive /tmp/x",
        "rm --recursive=yes --force /tmp/x",
        "chmod 777 -R /tmp/x",
        "chmod -R 777 /tmp/x",
        "chmod --recursive 777 /tmp/x",
        "chmod 777 --recursive /tmp/x",
        "git clean -xdf",
        "git clean -fd -x",
        "git clean --force -dx",
        "git push origin main --force",
        "git reset HEAD~1 --hard",
    ] {
        assert!(is_denied(command), "{command} must be denied");
    }
    for command in [
        "rm -f /tmp/x",
        "rm -r /tmp/x",
        "rm --force /tmp/x",
        "rm /tmp/x",
        "chmod -R 755 /tmp/x",
        "chmod 777 /tmp/x",
        "chmod -R - 777 /tmp/x",
        "git push origin main",
        "git reset --soft HEAD~1",
    ] {
        assert!(!is_denied(command), "{command} must be allowed");
    }
}

/// The two exclusions documented on `DEFAULT_PROHIBITED_COMMANDS`: blocking
/// the safe alternative an agent is told to reach for would be worse than
/// the bypass this normalization closes.
#[test]
fn documented_exclusions_stay_allowed() {
    for command in [
        "git push --force-with-lease origin main",
        "git push --force-with-lease=origin/main origin main",
        "git push origin main --force-with-lease",
        "sudo git push --force-with-lease origin main",
        "git clean -fd",
        "git clean -ffd",
        "git clean -df",
        "git clean --force -d",
        "sudo git clean -ffd",
    ] {
        assert!(!is_denied(command), "{command} must stay allowed");
    }
}

#[test]
fn flags_after_the_end_of_options_marker_are_operands() {
    for command in [
        "rm -- -rf /tmp/x",
        "rm -- --recursive --force",
        "chmod -- -R 777",
        "git push -- --force",
    ] {
        assert!(
            !is_denied(command),
            "{command} names files, not flags, after --"
        );
    }
    assert!(
        is_denied("rm -rf -- /tmp/x"),
        "flags written before -- are still flags"
    );
}

#[test]
fn a_wrapped_deny_reason_names_the_stripped_prefix() {
    let bare = matched("rm -rf /tmp/x").expect("denied");
    assert_eq!(bare.reason(), "command matches prohibited_commands policy");

    let wrapped = matched("sudo -u root rm -rf /tmp/x").expect("denied");
    assert_eq!(
        wrapped.reason(),
        "command matches prohibited_commands policy after the wrapper prefix `sudo -u root`"
    );
}

/// A policy is authored by hand, so the spelling its author happened to pick
/// must not decide whether the rule ever fires. Asserted from the rule side
/// as well as the command side, because a long-form entry that silently
/// never matches is a bypass that a command-side table cannot see.
#[test]
fn long_and_short_policy_entries_produce_identical_verdicts() {
    let long = policy(&[
        "rm --recursive --force",
        "chmod --recursive 777",
        "git push --force",
    ]);
    let short = policy(&["rm -rf", "chmod -R 777", "git push -f"]);

    for command in [
        "rm -rf /tmp/x",
        "rm -r -f /tmp/x",
        "rm --recursive --force /tmp/x",
        "rm -r --force /tmp/x",
        "rm -f --recursive /tmp/x",
        "chmod -R 777 /tmp/x",
        "chmod 777 --recursive /tmp/x",
        "chmod --recursive 777 /tmp/x",
        "git push --force origin main",
        "git push -f origin main",
        "git push origin main --force",
    ] {
        assert!(
            is_denied_by(&long, command),
            "{command} must be denied by the long-form policy"
        );
        assert!(
            is_denied_by(&short, command),
            "{command} must be denied by the short-form policy"
        );
    }

    for command in [
        "rm -f /tmp/x",
        "rm -r /tmp/x",
        "chmod -R 755 /tmp/x",
        "git push --force-with-lease origin main",
        "git push origin main",
    ] {
        assert!(
            !is_denied_by(&long, command),
            "{command} must be allowed by the long-form policy"
        );
        assert!(
            !is_denied_by(&short, command),
            "{command} must be allowed by the short-form policy"
        );
    }

    // The one asymmetry, and it is deliberate: `--recursive` names both
    // short spellings, so a long-form entry also covers `-R`, while a
    // hand-written `-r` entry covers only what it spells. The shipped
    // defaults close this by listing the uppercase forms outright rather
    // than by folding case, which would make `-r` and `-R` interchangeable
    // for every executable.
    assert!(is_denied_by(&long, "rm -Rf /tmp/x"));
    assert!(!is_denied_by(&short, "rm -Rf /tmp/x"));
    assert!(is_denied("rm -Rf /tmp/x"));
    assert!(is_denied("rm -fR /tmp/x"));
}

/// `-r` and `-R` are synonyms for `rm` but distinct options elsewhere, so
/// they must not be silently interchangeable. The default policy lists the
/// `rm` uppercase forms explicitly rather than relying on case folding.
#[test]
fn short_flag_case_is_not_folded_away() {
    let upper = policy(&["ls -R"]);
    assert!(is_denied_by(&upper, "ls -R /tmp"));
    assert!(
        !is_denied_by(&upper, "ls -r /tmp"),
        "reverse order is not recursive"
    );
    assert!(is_denied_by(&upper, "ls --recursive /tmp"));
}

/// An attached short-option value must not be read as a cluster of flags:
/// `git push -oref` carries a push option, not a `-f` force flag, and
/// blocking it is the false positive this normalization exists to avoid.
#[test]
fn attached_short_option_values_are_not_read_as_flags() {
    for command in [
        "git push -ofoo origin main",
        "git push -oci.fast origin main",
        "git push -oref origin main",
        "git push --push-option=foo origin main",
        "git push -o force origin main",
    ] {
        assert!(!is_denied(command), "{command} must be allowed");
    }
    for command in [
        "git push -f origin main",
        "git push -fq origin main",
        "git clean -fdx",
    ] {
        assert!(
            is_denied(command),
            "{command} must still be denied after cluster splitting is restricted"
        );
    }
}

/// The deny reason reaches the agent and is written into the local evidence
/// record, so a secret handed to a wrapper must never survive into it.
#[test]
fn assignment_values_are_redacted_from_the_deny_reason() {
    let matched = matched("env API_TOKEN=s3cr3t-abc rm -rf /tmp/x").expect("denied");
    let reason = matched.reason();
    assert!(
        !reason.contains("s3cr3t-abc"),
        "a secret must not reach the deny reason: {reason}"
    );
    assert_eq!(
        reason,
        "command matches prohibited_commands policy after the wrapper prefix `env API_TOKEN=<redacted>`"
    );

    let optioned = deny_reason("sudo -u root rm -rf /tmp/x");
    assert!(
        optioned.contains("-u root"),
        "wrapper options stay visible so the match stays explainable: {optioned}"
    );

    // A secret can also arrive as the value of a wrapper option rather than
    // as a bare assignment, so redaction cannot key on position.
    let smuggled = deny_reason("env -S DEPLOY_KEY=hunter2 rm -rf /tmp/x");
    assert!(
        !smuggled.contains("hunter2"),
        "an option value must be redacted too: {smuggled}"
    );
    assert!(smuggled.contains("DEPLOY_KEY=<redacted>"), "{smuggled}");

    let option_value = deny_reason(&format!(
        "sudo --prompt=API_TOKEN=s3cr3t {}",
        recursive_remove()
    ));
    assert!(
        option_value.contains("--prompt=<redacted>"),
        "the option name must stay visible: {option_value}"
    );
    assert!(
        !option_value.contains("s3cr3t"),
        "an option value must not reach the deny reason: {option_value}"
    );

    let valueless_option = deny_reason(&format!("sudo -i {}", recursive_remove()));
    assert!(
        valueless_option.contains("sudo -i"),
        "a valueless option must stay visible: {valueless_option}"
    );
}

/// Build the command used by the documented parser-differential cases without
/// duplicating one policy entry in each test string.
fn recursive_remove() -> String {
    format!("rm -{}{} /tmp/x", "r", "f")
}

/// Walk the repository documentation so the scope check covers new Markdown
/// files without maintaining a second hand-written file list.
fn collect_markdown_files(path: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_markdown_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "md") {
            files.push(path);
        }
    }
}

/// Identify sentences that describe policy blocking without the guardrail
/// scope that makes the claim honest.
fn has_unscoped_blocking_claim(sentence: &str) -> bool {
    let sentence = sentence.to_ascii_lowercase();
    let names_policy = sentence.contains("destructive") || sentence.contains("prohibited command");
    let claims_block = ["block", "refus", "deny", "protect", "prevent"]
        .iter()
        .any(|verb| sentence.contains(verb));
    let has_scope = sentence.contains("guardrail")
        && (sentence.contains("accidental") || sentence.contains("not a security boundary"));
    names_policy && claims_block && !has_scope
}

#[test]
fn documented_evasion_surface_stays_in_sync() {
    let command = recursive_remove();
    for wrapped in [
        format!(r#"sh -c "{command}""#),
        format!("echo `{command}`"),
        format!("echo $({command})"),
        format!("printf ok | {command}"),
        format!("env -S {command}"),
        format!("env --split-string={command}"),
        "git -C /repo reset --hard HEAD~1".to_string(),
        "git -c foo=bar push --force origin main".to_string(),
        format!("/bin/{command}"),
        format!("alias {}='{}'; {command}", "rm", command),
        format!("{}{}", ["mk", "fs"].concat(), ".ext4 /dev/x"),
    ] {
        assert!(
            !is_denied(&wrapped),
            "documented evasion must stay allowed: {wrapped}"
        );
    }

    let non_clusterable = policy(&["tar -x -z"]);
    assert!(!is_denied_by(&non_clusterable, "tar -xz archive.tar"));
    assert!(is_denied_by(&non_clusterable, "tar -x -z archive.tar"));

    let clusterable = vec![argv(&format!("rm -{} -{}", "r", "f"))];
    assert!(is_denied_by(&clusterable, &command));
}

#[test]
fn documentation_scopes_destructive_command_blocking_claims() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![root.join("README.md")];
    collect_markdown_files(&root.join("doc"), &mut files);
    // Published release notes record what a release claimed when it shipped and
    // are not rewritten afterward, the same rule `doc/adr/README.md` states for
    // decision records. Scoping applies to documentation describing current
    // behavior; an overclaim in a shipped note is corrected by the next note.
    let releases = root.join("doc").join("releases");
    for file in files
        .into_iter()
        .filter(|file| !file.starts_with(&releases))
    {
        let contents = std::fs::read_to_string(&file).expect("documentation is readable");
        for sentence in contents.split(['.', '!', '?']) {
            assert!(
                !has_unscoped_blocking_claim(sentence),
                "unscoped command-blocking claim in {}: {sentence}",
                file.display()
            );
        }
    }
}

#[test]
fn detects_direct_git_commit_segments_without_matching_prose() {
    for command in [
        "git commit -m fix",
        "/usr/bin/git commit --amend",
        "git -C /repo commit -m fix",
        "git add src/lib.rs && git commit -m fix",
        "env MODE=test git commit -m fix",
    ] {
        assert!(
            invokes_git_commit(command),
            "commit not detected: {command}"
        );
    }
    for command in [
        "git status",
        "git commit-tree HEAD",
        "echo git commit",
        "echo 'git commit'",
        "sh -c 'git commit -m nested'",
    ] {
        assert!(
            !invokes_git_commit(command),
            "non-commit matched: {command}"
        );
    }
}
